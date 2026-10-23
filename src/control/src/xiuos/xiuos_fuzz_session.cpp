// Copyright 2026 reFuzz project author -------youngkk.
//
// XiuosFuzzSession impl. See header for design notes.

#include "refuzz/control/xiuos/xiuos_fuzz_session.hpp"

#include "util/json.hpp"

#include "refuzz/channel/factory/channel_catalog.hpp"
#include "refuzz/channel/factory/xiuos_uart_profile.hpp"
#include "refuzz/feedback/aggregator/coverage_guided_aggregator.hpp"
#include "refuzz/feedback/signal/xiuos_coverage_signal.hpp"
#include "refuzz/feedback/signal/xiuos_oracle_signal.hpp"
#include "refuzz/proto_domain/combined_crash_event.hpp"
#include "refuzz/proto_domain/types.hpp"  // proto::ResultCode
#include "refuzz/program/xiuos/xiuos_program.hpp"
#include "refuzz/program/xiuos/xiuos_program_seed.hpp"
#include "refuzz/scheduler/policy/round_robin_policy.hpp"

#include <sys/stat.h>

#include <algorithm>
#include <cstdio>
#include <deque>
#include <fstream>
#include <memory>
#include <random>
#include <sstream>
#include <system_error>
#include <utility>

namespace refuzz::control::xiuos {

namespace channel   = refuzz::channel;
namespace cc        = refuzz::core::channel_contract;
namespace fuzzer    = refuzz::fuzzer;
namespace factory   = refuzz::channel::factory;
namespace progxiuos = refuzz::program::xiuos;

namespace {

bool PathExists(const std::string& s) {
    struct stat st{};
    return ::stat(s.c_str(), &st) == 0;
}

// FNV-1a 64-bit, same family as XiuosCrashBucket's payload dedup. Stable
// across runs so resume-from-disk dedup works.
std::uint64_t FnvHash64(const std::vector<std::uint8_t>& buf) {
    std::uint64_t h = 0xcbf29ce484222325ull;
    for (auto b : buf) {
        h ^= b;
        h *= 0x100000001b3ull;
    }
    return h;
}

std::string HexHash(std::uint64_t h) {
    std::ostringstream os;
    os.fill('0');
    os.width(16);
    os << std::hex << h;
    return os.str();
}

// Decode wire payload (program + 20-byte call records) into a XiUOS C
// program that, when run as a task body, reproduces the wedge. Mirrors the
// worker's per-call dispatch + end-of-program slot cleanup so the kernel
// gets the same K* call sequence that the wedged session triggered.
std::string DecodePayloadToC(const std::vector<std::uint8_t>& payload,
                             const std::string& stem) {
    auto rd32 = [&](std::size_t off) -> std::uint32_t {
        return (std::uint32_t(payload[off]) << 24) |
               (std::uint32_t(payload[off+1]) << 16) |
               (std::uint32_t(payload[off+2]) << 8) |
                std::uint32_t(payload[off+3]);
    };
    std::ostringstream os;
    os << "/* reFuzz auto-generated repro for wedge 0x" << stem << "\n"
       << " * Drop into a XiUOS app as the task body to reproduce.\n"
       << " * Mirrors kernel/refuzz/refuzz_worker.c dispatch + cleanup.\n"
       << " */\n"
       << "#include <xizi.h>\n\n"
       << "static void _refuzz_noop_cb(void *p) { (void)p; }\n"
       << "static void _refuzz_victim_sleep_forever(void) {\n"
       << "    while (RET_TRUE) { (void)MdelayKTask(10); }\n"
       << "}\n"
       << "static void _refuzz_victim_obtain_sem(void *p) {\n"
       << "    (void)KSemaphoreObtain((int32)(uintptr_t)p, WAITING_FOREVER);\n"
       << "    _refuzz_victim_sleep_forever();\n"
       << "}\n"
       << "static void _refuzz_victim_process_event(void *p) {\n"
       << "    uint32 _pp = 0;\n"
       << "    (void)KEventProcess((int32)(uintptr_t)p, 0x1FFFFFFFu,\n"
       << "                        EVENT_OR | EVENT_AUTOCLEAN, WAITING_FOREVER, &_pp);\n"
       << "    _refuzz_victim_sleep_forever();\n"
       << "}\n"
       << "static void _refuzz_victim_recv_msgq(void *p) {\n"
       << "    char _b[16];\n"
       << "    (void)KMsgQueueRecv((int32)(uintptr_t)p, _b, sizeof(_b), WAITING_FOREVER);\n"
       << "    _refuzz_victim_sleep_forever();\n"
       << "}\n"
       << "extern void DeInitWorkQueue(WorkqueueType *p_queue);\n"
       << "static void _refuzz_noop_work_cb(struct Work *w, void *d) { (void)w; (void)d; }\n\n"
       << "/* Lookup tables copied from refuzz_worker.c */\n"
       << "static const int32 _ticks[4] = {10, 20, 50, 100};\n"
       << "static const uint8 _modes[4] = {TIMER_TRIGGER_ONCE,"
                                          "TIMER_TRIGGER_PERIODIC,"
                                          "TIMER_TRIGGER_ONCE,"
                                          "TIMER_TRIGGER_PERIODIC};\n"
       << "static const uint32 _msz[4]  = {4, 8, 16, 16};\n"
       << "static const uint32 _mn[4]   = {1, 2, 4, 8};\n"
       << "static inline int32 _norm_to(uint32 r) {\n"
       << "    static const int32 t[4] = {0, 0, 1, 1};\n"
       << "    return t[r & 0x03];\n"
       << "}\n\n"
       << "int refuzz_replay_" << stem.substr(0, 12) << "(void) {\n"
       << "    int32 sem[4]={-1,-1,-1,-1}, mtx[4]={-1,-1,-1,-1};\n"
       << "    int32 mq[4]={-1,-1,-1,-1},  ev[4]={-1,-1,-1,-1};\n"
       << "    int32 tm[4]={-1,-1,-1,-1};\n"
       << "    int32 vt[4]={-1,-1,-1,-1};   /* victim task ids */\n"
       << "    WorkqueueType* wq[4] = {NONE, NONE, NONE, NONE};\n"
       << "    static struct Work _wqw[4];\n"
       << "    static const uint8 _wq_prios[4] = {6, 7, 8, 10};\n"
       << "    uint32 mqsz[4]={0};\n"
       << "    int32 ret = 0;\n"
       << "    char scratch[16] = {0};\n";

    if (payload.size() < 4) {
        os << "    /* empty/short payload */\n    return ret;\n}\n";
        return os.str();
    }
    const std::uint8_t call_count = payload[2];
    constexpr std::size_t CALL_SIZE = 20;
    for (std::uint8_t i = 0; i < call_count; ++i) {
        const std::size_t base = 4 + i * CALL_SIZE;
        if (base + CALL_SIZE > payload.size()) break;
        const std::uint8_t api = payload[base];
        const std::uint32_t a0 = rd32(base + 4);
        const std::uint32_t a1 = rd32(base + 8);
        const std::uint32_t a2 = rd32(base + 12);
        const std::uint32_t slot = a0 & 0x03;  // worker uses RefuzzNormalizeIdx4
        os << "    /* call[" << int(i) << "] api=0x"
           << std::hex << int(api) << std::dec << " */\n";
        switch (api) {
        case 0x01:  // SEM_CREATE(slot, value)
            os << "    if (sem[" << slot << "] >= 0) KSemaphoreDelete(sem[" << slot << "]);\n"
               << "    sem[" << slot << "] = KSemaphoreCreate(" << (a1 & 0xFFFF) << ");\n"
               << "    ret = sem[" << slot << "];\n"; break;
        case 0x02:  // SEM_OBTAIN
            os << "    ret = (sem[" << slot << "]<0) ? -ERROR : KSemaphoreObtain(sem[" << slot << "], _norm_to(" << a1 << "));\n"; break;
        case 0x03:  // SEM_ABANDON
            os << "    ret = (sem[" << slot << "]<0) ? -ERROR : KSemaphoreAbandon(sem[" << slot << "]);\n"; break;
        case 0x04:  // SEM_SET_VALUE
            os << "    ret = (sem[" << slot << "]<0) ? -ERROR : KSemaphoreSetValue(sem[" << slot << "], " << (a1 & 0xFFFF) << ");\n"; break;
        case 0x05:  // SEM_DELETE
            os << "    if (sem[" << slot << "] >= 0) { KSemaphoreDelete(sem[" << slot << "]); sem[" << slot << "]=-1; ret = 0; } else ret = -ERROR;\n"; break;
        case 0x10:  // MUTEX_CREATE
            os << "    if (mtx[" << slot << "] >= 0) KMutexDelete(mtx[" << slot << "]);\n"
               << "    mtx[" << slot << "] = KMutexCreate(); ret = mtx[" << slot << "];\n"; break;
        case 0x11:  // MUTEX_OBTAIN
            os << "    ret = (mtx[" << slot << "]<0) ? -ERROR : KMutexObtain(mtx[" << slot << "], _norm_to(" << a1 << "));\n"; break;
        case 0x12:  // MUTEX_ABANDON
            os << "    ret = (mtx[" << slot << "]<0) ? -ERROR : KMutexAbandon(mtx[" << slot << "]);\n"; break;
        case 0x13:  // MUTEX_DELETE
            os << "    if (mtx[" << slot << "] >= 0) { KMutexDelete(mtx[" << slot << "]); mtx[" << slot << "]=-1; ret = 0; } else ret = -ERROR;\n"; break;
        case 0x20: { // MSGQ_CREATE(slot, size_idx, count_idx)
            const std::uint32_t sz = a1 & 0x03;
            const std::uint32_t cn = a2 & 0x03;
            os << "    if (mq[" << slot << "] >= 0) { KDeleteMsgQueue(mq[" << slot << "]); mq[" << slot << "]=-1; }\n"
               << "    mq[" << slot << "] = KCreateMsgQueue(_msz[" << sz << "], _mn[" << cn << "]);\n"
               << "    mqsz[" << slot << "] = _msz[" << sz << "]; ret = mq[" << slot << "];\n";
            break;
        }
        case 0x21:  // MSGQ_DELETE
            os << "    if (mq[" << slot << "] >= 0) { ret = KDeleteMsgQueue(mq[" << slot << "]); mq[" << slot << "]=-1; } else ret = -ERROR;\n"; break;
        case 0x22:  // MSGQ_SEND
            os << "    ret = (mq[" << slot << "]<0) ? -ERROR : KMsgQueueSendwait(mq[" << slot << "], scratch, mqsz[" << slot << "], 0);\n"; break;
        case 0x23:  // MSGQ_URGENT_SEND
            os << "    ret = (mq[" << slot << "]<0) ? -ERROR : KMsgQueueUrgentSend(mq[" << slot << "], scratch, mqsz[" << slot << "]);\n"; break;
        case 0x24:  // MSGQ_RECV
            os << "    ret = (mq[" << slot << "]<0) ? -ERROR : KMsgQueueRecv(mq[" << slot << "], scratch, mqsz[" << slot << "], _norm_to(" << a1 << "));\n"; break;
        case 0x25:  // MSGQ_REINIT
            os << "    ret = (mq[" << slot << "]<0) ? -ERROR : KMsgQueueReinit(mq[" << slot << "]);\n"; break;
        case 0x30:  // EVENT_CREATE
            os << "    if (ev[" << slot << "] >= 0) KEventDelete(ev[" << slot << "]);\n"
               << "    ev[" << slot << "] = KEventCreate(0); ret = ev[" << slot << "];\n"; break;
        case 0x31:  // EVENT_DELETE
            os << "    if (ev[" << slot << "] >= 0) { KEventDelete(ev[" << slot << "]); ev[" << slot << "]=-1; ret = 0; } else ret = -ERROR;\n"; break;
        case 0x32:  // EVENT_TRIGGER
            os << "    ret = (ev[" << slot << "]<0) ? -ERROR : KEventTrigger(ev[" << slot << "], 1u<<(" << (a1 & 0x03) << "));\n"; break;
        case 0x33: { // EVENT_PROCESS
            uint32_t processed = 0; (void)processed;
            os << "    { uint32 _p=0; ret = (ev[" << slot << "]<0) ? -ERROR : KEventProcess(ev[" << slot << "], 1u<<(" << (a1 & 0x03) << "), EVENT_OR|EVENT_AUTOCLEAN, _norm_to(" << a2 << "), &_p); }\n";
            break;
        }
        case 0x40: { // TIMER_CREATE(slot, ticks_idx, mode_idx)
            const std::uint32_t ti = a1 & 0x03;
            const std::uint32_t mi = a2 & 0x03;
            os << "    if (tm[" << slot << "] >= 0) { KTimerQuitRun(tm[" << slot << "]); KDeleteTimer(tm[" << slot << "]); tm[" << slot << "]=-1; }\n"
               << "    tm[" << slot << "] = KCreateTimer(\"r\", _refuzz_noop_cb, NONE, _ticks[" << ti << "], _modes[" << mi << "]); ret = tm[" << slot << "];\n";
            break;
        }
        case 0x41:  // TIMER_DELETE
            os << "    if (tm[" << slot << "] >= 0) { KTimerQuitRun(tm[" << slot << "]); ret = KDeleteTimer(tm[" << slot << "]); tm[" << slot << "]=-1; } else ret = -ERROR;\n"; break;
        case 0x42:  // TIMER_START_RUN
            os << "    ret = (tm[" << slot << "]<0) ? -ERROR : KTimerStartRun(tm[" << slot << "]);\n"; break;
        case 0x43:  // TIMER_QUIT_RUN
            os << "    ret = (tm[" << slot << "]<0) ? -ERROR : KTimerQuitRun(tm[" << slot << "]);\n"; break;
        case 0x44:  // TIMER_MODIFY
            os << "    ret = (tm[" << slot << "]<0) ? -ERROR : KTimerModify(tm[" << slot << "], _ticks[" << (a1 & 0x03) << "]);\n"; break;
        case 0x50: { // TASK_SPAWN_BLOCK_SEM(task_slot, sem_slot)
            const std::uint32_t tgt = a1 & 0x03;
            os << "    if (vt[" << slot << "] >= 0) { KTaskDelete(vt[" << slot << "]); vt[" << slot << "]=-1; }\n"
               << "    if (sem[" << tgt << "] >= 0) {\n"
               << "        int32 _vid = KTaskCreate(\"v_sem\", _refuzz_victim_obtain_sem, (void*)(uintptr_t)sem[" << tgt << "], 1024, 6);\n"
               << "        if (_vid >= 0) { StartupKTask(_vid); vt[" << slot << "] = _vid; ret = 0; } else ret = _vid;\n"
               << "    } else ret = -ERROR;\n";
            break;
        }
        case 0x51: { // TASK_SPAWN_BLOCK_EVENT
            const std::uint32_t tgt = a1 & 0x03;
            os << "    if (vt[" << slot << "] >= 0) { KTaskDelete(vt[" << slot << "]); vt[" << slot << "]=-1; }\n"
               << "    if (ev[" << tgt << "] >= 0) {\n"
               << "        int32 _vid = KTaskCreate(\"v_ev\", _refuzz_victim_process_event, (void*)(uintptr_t)ev[" << tgt << "], 1024, 6);\n"
               << "        if (_vid >= 0) { StartupKTask(_vid); vt[" << slot << "] = _vid; ret = 0; } else ret = _vid;\n"
               << "    } else ret = -ERROR;\n";
            break;
        }
        case 0x52: { // TASK_SPAWN_BLOCK_MSGQ_RECV
            const std::uint32_t tgt = a1 & 0x03;
            os << "    if (vt[" << slot << "] >= 0) { KTaskDelete(vt[" << slot << "]); vt[" << slot << "]=-1; }\n"
               << "    if (mq[" << tgt << "] >= 0) {\n"
               << "        int32 _vid = KTaskCreate(\"v_mq\", _refuzz_victim_recv_msgq, (void*)(uintptr_t)mq[" << tgt << "], 1024, 6);\n"
               << "        if (_vid >= 0) { StartupKTask(_vid); vt[" << slot << "] = _vid; ret = 0; } else ret = _vid;\n"
               << "    } else ret = -ERROR;\n";
            break;
        }
        case 0x53:  // TASK_TERMINATE
            os << "    if (vt[" << slot << "] >= 0) { KTaskDelete(vt[" << slot << "]); vt[" << slot << "]=-1; ret = 0; } else ret = -ERROR;\n"; break;
        case 0x54: { // TASK_PRIO_SET(task_slot, prio_idx)
            const std::uint32_t pi = a1 & 0x03;
            os << "    ret = (vt[" << slot << "] < 0) ? -ERROR : KTaskPrioSet(vt[" << slot << "], _wq_prios[" << pi << "]);\n";
            break;
        }
        case 0x60: { // WQ_CREATE(slot, prio_idx)
            const std::uint32_t pi = a1 & 0x03;
            os << "    if (wq[" << slot << "] != NONE) { DeInitWorkQueue(wq[" << slot << "]); wq[" << slot << "] = NONE; }\n"
               << "    wq[" << slot << "] = CreateWorkQueue(\"r_wq\", 1024, _wq_prios[" << pi << "]);\n"
               << "    if (wq[" << slot << "] != NONE) { WorkInit(&_wqw[" << slot << "], _refuzz_noop_work_cb, NONE); ret = 0; } else ret = -ERROR;\n";
            break;
        }
        case 0x61:  // WQ_DEINIT
            os << "    if (wq[" << slot << "] != NONE) { DeInitWorkQueue(wq[" << slot << "]); wq[" << slot << "] = NONE; ret = 0; } else ret = -ERROR;\n"; break;
        case 0x62:  // WQ_SUBMIT
            os << "    ret = (wq[" << slot << "] == NONE) ? -ERROR : WorkSubmit_immediate(wq[" << slot << "], &_wqw[" << slot << "]);\n"; break;
        case 0x63: { // WQ_SUBMIT_DELAYED(slot, time_idx)
            const std::uint32_t ti = a1 & 0x03;
            os << "    ret = (wq[" << slot << "] == NONE) ? -ERROR : WorkSubmit(wq[" << slot << "], &_wqw[" << slot << "], _ticks[" << ti << "]);\n";
            break;
        }
        case 0x90:  // RESOURCE_SNAPSHOT
            os << "    /* RESOURCE_SNAPSHOT is a reFuzz worker oracle-only introspection op; no XiUOS kernel API equivalent. */\n";
            break;
        default:
            os << "    /* unknown api 0x" << std::hex << int(api) << std::dec << " */\n"; break;
        }
    }
    os << "\n    /* End-of-program cleanup (matches RefuzzCleanupSlots).\n"
       << "     * WQs first (drain WQ task), then tasks, then resources.\n"
       << "     * Wedge typically triggers inside one of these calls. */\n"
       << "    for (int i = 0; i < 4; i++) {\n"
       << "        if (wq[i]  != NONE) { DeInitWorkQueue(wq[i]); wq[i] = NONE; }\n"
       << "    }\n"
       << "    for (int i = 0; i < 4; i++) {\n"
       << "        if (vt[i]  >= 0) KTaskDelete(vt[i]);\n"
       << "    }\n"
       << "    for (int i = 0; i < 4; i++) {\n"
       << "        if (sem[i] >= 0) KSemaphoreDelete(sem[i]);\n"
       << "        if (mtx[i] >= 0) KMutexDelete(mtx[i]);\n"
       << "        if (mq[i]  >= 0) KDeleteMsgQueue(mq[i]);\n"
       << "        if (ev[i]  >= 0) KEventDelete(ev[i]);\n"
       << "        if (tm[i]  >= 0) { KTimerQuitRun(tm[i]); KDeleteTimer(tm[i]); }\n"
       << "    }\n"
       << "    return ret;\n"
       << "}\n";
    return os.str();
}

}  // namespace

// ──────────────────────── ctor / dtor ───────────────────────────────────

XiuosFuzzSession::XiuosFuzzSession(Config cfg)
    : cfg_(std::move(cfg)),
      mutator_(cfg_.mutator_cfg),
      bucket_(cfg_.crash_bucket_dir),
      inbox_(/*cap=*/2048),
      manager_(store_, sched_handle_, inbox_,
               /*max_drain=*/256),
      fb_engine_("xiuos_kcov") {
    // sched_handle_ defaults to nullptr-pointing; bind it to scheduler_
    // before the manager actually pumps Tick. ApplyFiltersFromStore /
    // OnSeedAdded only fire from manager_.Tick(), which we never call
    // before this assignment.
    sched_handle_.Store(&scheduler_);
    scheduler_.RegisterPolicy("round_robin",
                              std::make_unique<fuzzer::RoundRobinPolicy>());

    fb_engine_.AddSignal(std::make_unique<fuzzer::XiuosCoverageSignal>());
    // Per-program invariant oracle (heap/state corruption + leak): classifies
    // the worker's RESULT vendor_status/vendor_flags verdict into a crash_payload
    // finding, so detection lives in the feedback module (not hand-handled in
    // the loop). Its crash_payload flows aggregator → EngineOutput.crash_dispatch.
    fb_engine_.AddSignal(std::make_unique<fuzzer::XiuosOracleSignal>());
    fb_engine_.SetAggregator(std::make_unique<fuzzer::CoverageGuidedAggregator>());
    // [verdict 重构] 不再 SetDispatcher / 构造 actions_:feedback 只产 verdict,
    // admit / scheduler-notify 由 AdmitFromVerdict 在 Process(ev) 后编排。
}

// [verdict 重构] 承接旧 actions_ + CorpusAdmitDispatcher 的 admit/notify 职责。
void XiuosFuzzSession::AdmitFromVerdict(
    const refuzz::core::channel_contract::ChannelEvent& ev,
    const refuzz::fuzzer::EngineOutput& out)
{
    const refuzz::core::channel_contract::CompletionContext* cc = nullptr;
    if (auto* c = ev.AsCompletion()) cc = &c->ctx;
    else if (auto* a = ev.AsAbnormal()) cc = &a->ctx;
    if (cc == nullptr) {
        return;  // fault：无 ctx
    }
    // scheduler disposition(自映射 boost/cool/neutral)。
    scheduler_.OnFeedback(cc->seed_id, out.verdict.disposition);
    // 准入:manager_ 默认 kInteresting,等价旧 CorpusAdmitDispatcher(interesting-gate
    // + canonical materialize + artifact + priority + kMutation + inbox_.TryPush)。
    // [mab lineage Step A] control classifies the origin; corpus just stamps it.
    const uint64_t lineage_parent = cc->seed_id;
    const auto lineage_origin = (lineage_parent == 0) ? fuzzer::SeedOrigin::kGenerate
                                                      : fuzzer::SeedOrigin::kMutate;
    manager_.OfferVerdict(cc->program_payload, cc->artifact, out.verdict,
                          fuzzer::SeedSource::kMutation,
                          /*divert_to_caller=*/false, next_seed_id_,
                          lineage_origin, lineage_parent);
}

XiuosFuzzSession::~XiuosFuzzSession() {
    Close();
}

// ──────────────────────── Boot / Close ──────────────────────────────────

XiuosFuzzSession::BootStatus XiuosFuzzSession::Boot() {
    if (booted_) return BootStatus::kOk;
    if (!PathExists(cfg_.elf_path)) {
        return BootStatus::kSkippedMissingElf;
    }
    if (!std::filesystem::exists(cfg_.corpus_root)) {
        return BootStatus::kSkippedMissingCorpus;
    }

    // Crash bucket dir handling. The XiuosCrashBucket ctor already
    // create_directories'd it; honor reset_bucket_dir_on_boot by wiping
    // first if asked, then reload so in-memory dedup mirrors disk. With
    // reset=true this clears any previous in-memory bucket state; with
    // reset=false it makes resume semantics real.
    // Default wedge_bucket_dir to vm_workdir/wedges (co-located with the
    // implicit crash_bucket_dir).
    if (cfg_.wedge_bucket_dir.empty()) {
        cfg_.wedge_bucket_dir = cfg_.vm_workdir / "wedges";
    }
    if (cfg_.reset_bucket_dir_on_boot) {
        std::error_code ec;
        std::filesystem::remove_all(cfg_.crash_bucket_dir, ec);
        std::filesystem::create_directories(cfg_.crash_bucket_dir, ec);
        std::filesystem::remove_all(cfg_.wedge_bucket_dir, ec);
    }
    (void)bucket_.LoadFromDisk();
    // Per-bug subdir layout (transient + archive): <dir>/wedge_<16hex>/
    //   ├── program.bin   raw wire payload
    //   ├── meta.json     metadata
    //   └── repro.c       auto-emitted XiUOS C repro
    // Dedup at Boot: scan subdirs whose name starts with `wedge_`.
    auto scan_dedup = [](const std::filesystem::path& dir,
                         std::unordered_set<std::uint64_t>& out) {
        std::error_code ec;
        if (!std::filesystem::exists(dir, ec)) return;
        for (const auto& e : std::filesystem::directory_iterator(dir, ec)) {
            if (!e.is_directory()) continue;
            const auto name = e.path().filename().string();
            if (name.size() == 22 && name.rfind("wedge_", 0) == 0) {
                try {
                    out.insert(std::stoull(name.substr(6), nullptr, 16));
                } catch (...) {}
            }
        }
    };
    {
        std::error_code ec;
        std::filesystem::create_directories(cfg_.wedge_bucket_dir, ec);
        scan_dedup(cfg_.wedge_bucket_dir, wedge_dedup_);
    }
    if (!cfg_.findings_archive_dir.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(cfg_.findings_archive_dir, ec);
        scan_dedup(cfg_.findings_archive_dir, archive_dedup_);
    }

    if (!BuildAndBootChannel()) return BootStatus::kError;

    booted_ = true;
    closed_ = false;
    return BootStatus::kOk;
}

bool XiuosFuzzSession::BuildAndBootChannel() {
    channel::ChannelCatalog catalog;
    channel::RegisterBuiltinChannels(catalog);

    factory::XiuosUartProfile profile;
    profile.qemu_bin    = cfg_.qemu_bin;
    profile.elf_path    = cfg_.elf_path;
    profile.serial_host = cfg_.serial_host;
    profile.serial_port = cfg_.serial_port;

    channel::ChannelBuildContext bctx;
    bctx.channel_cfg.channel_id            = cfg_.channel_id;
    bctx.channel_cfg.n_workers             = 1;
    bctx.channel_cfg.wait_ready_timeout    = cfg_.wait_ready_timeout;
    bctx.channel_cfg.loop_interval         = cfg_.loop_interval;
    bctx.channel_cfg.input_queue_capacity  = cfg_.channel_inflight_capacity;
    bctx.backend_profile                   = &profile;
    bctx.vm_index                          = 0;
    bctx.vm_workdir                        = cfg_.vm_workdir.string();

    auto build_r = catalog.Build(
        std::string(channel::channel_backend_id::kQemuUartXiuos), bctx);
    if (!build_r.has_value()) {
        return false;
    }
    chan_ = std::move(build_r.value());
    if (chan_ == nullptr) return false;

    if (auto r = chan_->Boot(); !r.ok()) {
        chan_.reset();
        return false;
    }
    return true;
}

// Health-check: submit an empty program on the current (just-recovered)
// channel and wait briefly for a terminal event.
// Returns true iff a Completion matching our executor lands within the
// configured window. If the channel can't even round-trip the empty
// case, the host side has a problem and the upcoming verify should be
// classified as health_failed (not as "the candidate is spurious").
bool XiuosFuzzSession::WedgeHealthCheck() {
    if (!chan_) return false;
    // An empty program (call_count == 0) exercises the full wire round-trip
    // -- frame decode, header validation, RefuzzSendResult -- and proves the
    // worker is alive and responsive, while RefuzzExecuteCall is never
    // entered, so no kernel object is created or destroyed. That keeps id
    // managers and heap layout identical to a never-health-checked worker.
    const auto payload = refuzz::program::xiuos::XiuosEncodeProgram(
        std::span<const refuzz::program::xiuos::XiuosProgramCall>(),
        refuzz::program::xiuos::XiuosSuiteId::CommonKernel);

    cc::ChannelDispatchRequest req;
    req.executor_id      = ++next_executor_id_;
    req.seed_id          = 0;
    req.origin_seed_id   = 0;
    req.payload          = payload;
    req.timeout_ms       = cfg_.exec_timeout_ms;
    req.target_worker_id = 0;
    auto submit = chan_->Submit(req, std::chrono::microseconds(0));
    std::size_t retries = 0;
    while (submit.status == cc::ChannelSubmitStatus::kBusy && retries < 50) {
        DrainEventsAndFeedback(std::chrono::milliseconds(20));
        submit = chan_->Submit(req, std::chrono::microseconds(0));
        ++retries;
    }
    if (submit.status != cc::ChannelSubmitStatus::kAccepted) return false;

    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(cfg_.wedge_health_check_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        channel::EventList events;
        chan_->DrainEvents(events, std::chrono::milliseconds(100));
        for (const auto& ev : events) {
            if (ev.IsCompletion()) {
                ++stats_.total_completions;
                if (ev.AsCompletion() &&
                    ev.AsCompletion()->ctx.executor_id == req.executor_id) {
                    return true;
                }
            } else if (ev.IsAbnormal() && ev.AsAbnormal()) {
                ++stats_.total_abnormals;
                if (ev.AsAbnormal()->ctx.executor_id == req.executor_id) {
                    return false;  // worker died on a trivial program
                }
            }
            { const auto _out = fb_engine_.Process(ev); AdmitFromVerdict(ev, _out); }
        }
        DrainTickToFixpoint();
    }
    return false;  // health-check did not produce a terminal in window
}

bool XiuosFuzzSession::VerifyWedgeOnFresh(
        const std::vector<std::uint8_t>& payload,
        std::uint64_t orig_seed_id) {
    if (!chan_) return false;

    // Step 0 — optional health check: confirm the fresh channel can
    // round-trip a trivial program before we attribute a non-response to
    // the candidate payload. Failures here are NOT spurious-candidate
    // evidence; they're host-side problems.
    if (cfg_.wedge_health_check_enabled && !WedgeHealthCheck()) {
        ++stats_.wedge_verify_health_failed;
        return false;
    }

    cc::ChannelDispatchRequest req;
    req.executor_id      = ++next_executor_id_;
    req.seed_id          = orig_seed_id;
    req.origin_seed_id   = orig_seed_id;
    req.payload          = payload;
    req.timeout_ms       = cfg_.exec_timeout_ms;
    req.target_worker_id = 0;

    auto submit = chan_->Submit(req, std::chrono::microseconds(0));
    std::size_t retries = 0;
    while (submit.status == cc::ChannelSubmitStatus::kBusy && retries < 200) {
        DrainEventsAndFeedback(std::chrono::milliseconds(20));
        submit = chan_->Submit(req, std::chrono::microseconds(0));
        ++retries;
    }
    if (submit.status != cc::ChannelSubmitStatus::kAccepted) {
        ++stats_.wedge_verify_submit_failed;
        return false;
    }

    // Drain for verify_drain_ms (typically ≥ 2× initial). This window is
    // configurable so operators can widen it for slow boards without
    // touching code. The hardcoded 8s prior to 2026-05-23 conflated
    // candidate behavior with boot/host timing.
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(cfg_.wedge_verify_drain_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        channel::EventList events;
        chan_->DrainEvents(events, std::chrono::milliseconds(100));
        for (const auto& ev : events) {
            if (ev.IsCompletion()) {
                ++stats_.total_completions;
                if (ev.AsCompletion() &&
                    ev.AsCompletion()->ctx.executor_id == req.executor_id) {
                    ++stats_.wedge_verify_completed;
                    return false;  // re-submit completed → initial drain too tight
                }
            } else if (ev.IsAbnormal() && ev.AsAbnormal()) {
                ++stats_.total_abnormals;
                const auto idx =
                    static_cast<std::size_t>(ev.AsAbnormal()->kind);
                if (idx < stats_.abnormal_by_kind.size()) {
                    ++stats_.abnormal_by_kind[idx];
                }
                bucket_.Record(*ev.AsAbnormal());
                if (ev.AsAbnormal()->ctx.executor_id == req.executor_id) {
                    ++stats_.wedge_verify_abnormal;
                    return false;  // got a terminal abnormal (e.g. TRAP)
                }
            }
            { const auto _out = fb_engine_.Process(ev); AdmitFromVerdict(ev, _out); }
        }
        DrainTickToFixpoint();
    }
    ++stats_.wedge_verify_confirmed;
    return true;  // verify window expired → confirmed wedge
}

bool XiuosFuzzSession::RecoverFromWedge() {
    // Tear down current (wedged) channel. chan_->Close() stops QEMU + closes
    // data plane sockets. We then bump serial_port to avoid TIME_WAIT on the
    // same TCP serial endpoint, and rebuild.
    if (chan_) {
        chan_->Close();
        chan_.reset();
    }
    // Bump serial port; wrap if we ever overflow uint16 (extremely unlikely
    // in a single session, but stay correct).
    if (cfg_.serial_port < 0xFF00) {
        ++cfg_.serial_port;
    } else {
        cfg_.serial_port = 32500;
    }
    if (!BuildAndBootChannel()) {
        ++stats_.wedge_recovery_failures;
        return false;
    }
    ++stats_.wedge_recoveries;
    // Reset executor counter to a fresh page so post-recovery ids don't
    // collide with any stale inflight bookkeeping in our local state.
    next_executor_id_ += 0x10000ull;
    return true;
}

void XiuosFuzzSession::Close() {
    if (closed_) return;
    if (chan_) {
        chan_->Close();
        chan_.reset();
    }
    closed_ = true;
    booted_ = false;
}

// ──────────────────────── Drain helpers ─────────────────────────────────

void XiuosFuzzSession::DrainEventsAndFeedback(std::chrono::milliseconds budget) {
    if (!chan_) return;
    channel::EventList events;
    chan_->DrainEvents(events, budget);
    for (const auto& ev : events) {
        if (ev.IsCompletion()) {
            ++stats_.total_completions;
        } else if (ev.IsAbnormal() && ev.AsAbnormal()) {
            ++stats_.total_abnormals;
            const auto idx = static_cast<std::size_t>(ev.AsAbnormal()->kind);
            if (idx < stats_.abnormal_by_kind.size()) {
                ++stats_.abnormal_by_kind[idx];
            }
            bucket_.Record(*ev.AsAbnormal());
        }
        { const auto _out = fb_engine_.Process(ev); AdmitFromVerdict(ev, _out); }
    }
    DrainTickToFixpoint();
}

void XiuosFuzzSession::DrainTickToFixpoint() {
    // CorpusManager.Tick drains at most max_drain items per call. Loop
    // until store size stops changing or we hit a safe cap.
    for (int i = 0; i < 16; ++i) {
        const std::size_t before = store_.Size();
        manager_.Tick();
        if (store_.Size() == before) break;
    }
}

// ──────────────────────── Bootstrap ─────────────────────────────────────

std::size_t XiuosFuzzSession::Bootstrap() {
    if (!booted_ || !chan_) return 0;

    auto seed_paths = progxiuos::DiscoverXiuosProgramSeedFiles(cfg_.corpus_root);
    // Discovery sorts alphabetically; if multiple sub-trees exist (e.g.
    // generated/ + generated_ext/) a bootstrap_count smaller than the first
    // tree won't reach later trees. Deterministic shuffle by mutator rng_seed
    // gives each campaign a uniform-coverage sample while staying
    // reproducible per-mut_seed.
    {
        std::mt19937_64 rng(cfg_.mutator_cfg.rng_seed ^ 0xb007u);
        std::shuffle(seed_paths.begin(), seed_paths.end(), rng);
    }
    if (seed_paths.size() > cfg_.bootstrap_count) {
        seed_paths.resize(cfg_.bootstrap_count);
    }

    for (const auto& seed_path : seed_paths) {
        auto seed_r = progxiuos::LoadXiuosProgramSeed(seed_path);
        if (!seed_r.ok()) continue;
        const auto payload = seed_r.value().Encode();

        cc::ChannelDispatchRequest req;
        req.executor_id      = ++next_executor_id_;
        req.seed_id          = 0;
        req.origin_seed_id   = 0;
        req.payload          = payload;
        req.timeout_ms       = cfg_.exec_timeout_ms;
        req.target_worker_id = 0;

        auto submit = chan_->Submit(req, std::chrono::microseconds(0));
        std::size_t retries = 0;
        while (submit.status == cc::ChannelSubmitStatus::kBusy && retries < 200) {
            DrainEventsAndFeedback(std::chrono::milliseconds(20));
            submit = chan_->Submit(req, std::chrono::microseconds(0));
            ++retries;
        }
        if (submit.status != cc::ChannelSubmitStatus::kAccepted) continue;
        ++stats_.bootstrap_submits;

        // Drain at least one terminal event for THIS executor.
        const auto deadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(cfg_.wedge_initial_drain_ms);
        bool saw = false;
        while (!saw && std::chrono::steady_clock::now() < deadline) {
            channel::EventList events;
            chan_->DrainEvents(events, std::chrono::milliseconds(100));
            for (const auto& ev : events) {
                if (ev.IsCompletion()) {
                    ++stats_.total_completions;
                    if (ev.AsCompletion() &&
                        ev.AsCompletion()->ctx.executor_id == req.executor_id) {
                        saw = true;
                    }
                } else if (ev.IsAbnormal() && ev.AsAbnormal()) {
                    ++stats_.total_abnormals;
                    const auto idx = static_cast<std::size_t>(ev.AsAbnormal()->kind);
                    if (idx < stats_.abnormal_by_kind.size()) {
                        ++stats_.abnormal_by_kind[idx];
                    }
                    bucket_.Record(*ev.AsAbnormal());
                    if (ev.AsAbnormal()->ctx.executor_id == req.executor_id) {
                        saw = true;
                    }
                }
                { const auto _out = fb_engine_.Process(ev); AdmitFromVerdict(ev, _out); }
            }
            DrainTickToFixpoint();
        }

        // Same wedge handling as Step(): verify on fresh worker before
        // archiving. VerifyWedgeOnFresh updates the specific verify_*
        // counters (confirmed / completed / abnormal / submit_failed /
        // health_failed) internally — caller only needs the bool.
        if (!saw) {
            const auto candidate_payload = payload;
            if (!RecoverFromWedge()) {
                continue;
            }
            const bool reproduced =
                VerifyWedgeOnFresh(candidate_payload, /*orig_seed=*/0);
            if (reproduced) {
                RecordWedge(req.executor_id, /*seed_id=*/0, candidate_payload);
                (void)RecoverFromWedge();
            }
        }
    }

    stats_.corpus_after_bootstrap = store_.Size();
    stats_.corpus_current = stats_.corpus_after_bootstrap;
    return stats_.corpus_after_bootstrap;
}

// ──────────────────────── Step / RunLoop ────────────────────────────────

bool XiuosFuzzSession::Step() {
    if (!booted_ || !chan_) return false;

    const auto picked = scheduler_.NextSeedId();
    if (!picked.has_value()) {
        ++stats_.scheduler_nones;
        DrainEventsAndFeedback(std::chrono::milliseconds(20));
        return false;
    }
    seen_seed_ids_.insert(picked->seed_id);

    const auto handle = store_.GetSeed(picked->seed_id);
    if (handle == nullptr) return false;
    const auto mutated = mutator_.Mutate(*handle);
    if (mutated.empty()) return false;

    cc::ChannelDispatchRequest req;
    req.executor_id      = ++next_executor_id_;
    req.seed_id          = picked->seed_id;
    req.origin_seed_id   = picked->seed_id;
    req.payload          = mutated;
    req.timeout_ms       = cfg_.exec_timeout_ms;
    req.target_worker_id = 0;

    auto submit = chan_->Submit(req, std::chrono::microseconds(0));
    std::size_t retries = 0;
    while (submit.status == cc::ChannelSubmitStatus::kBusy && retries < 200) {
        DrainEventsAndFeedback(std::chrono::milliseconds(20));
        submit = chan_->Submit(req, std::chrono::microseconds(0));
        ++retries;
    }
    if (submit.status != cc::ChannelSubmitStatus::kAccepted) return false;
    ++stats_.loop_submits;

    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(cfg_.wedge_initial_drain_ms);
    bool saw = false;
    bool need_respawn = false;
    while (!saw && std::chrono::steady_clock::now() < deadline) {
        channel::EventList events;
        chan_->DrainEvents(events, std::chrono::milliseconds(100));
        for (const auto& ev : events) {
            if (ev.IsCompletion()) {
                ++stats_.total_completions;
                const auto* comp = ev.AsCompletion();
                if (comp && comp->ctx.executor_id == req.executor_id) {
                    saw = true;
                }
            } else if (ev.IsAbnormal() && ev.AsAbnormal()) {
                ++stats_.total_abnormals;
                const auto idx =
                    static_cast<std::size_t>(ev.AsAbnormal()->kind);
                if (idx < stats_.abnormal_by_kind.size()) {
                    ++stats_.abnormal_by_kind[idx];
                }
                bucket_.Record(*ev.AsAbnormal());
                if (ev.AsAbnormal()->ctx.executor_id == req.executor_id) {
                    saw = true;
                }
            }
            // Feedback engine: coverage admission (XiuosCoverageSignal) + the
            // per-program invariant oracle (XiuosOracleSignal). The oracle
            // classifies the worker's RESULT verdict (vendor_status / vendor_
            // flags) into a crash_payload finding — detection now lives in the
            // feedback module, not inline here. Consume the resulting
            // crash_dispatch (transitional sink until Stage 3 wires the crash
            // pipeline): a kCrashed finding is a hard heap/state corruption
            // (worker heap unsafe → respawn); anything else is a soft leak lead.
            const auto fb_out = fb_engine_.Process(ev);
            AdmitFromVerdict(ev, fb_out);
            if (fb_out.crash_dispatch.has_value() &&
                fb_out.crash_dispatch->crash_program.has_value() &&
                fb_out.crash_dispatch->crash_program->completion.has_value()) {
                const auto& cp = *fb_out.crash_dispatch->crash_program;
                const auto& summary = *cp.completion;
                const auto code = summary.crash_signal;
                if (summary.result_code == refuzz::proto::ResultCode::kCrashed) {
                    RecordStateViolation(cp.executor_id, cp.seed_id,
                                         static_cast<std::int32_t>(code),
                                         cp.program_payload);
                    need_respawn = true;
                } else {
                    RecordLeakLead(cp.executor_id, cp.seed_id, code,
                                   cp.program_payload);
                }
            }
        }
        DrainTickToFixpoint();
    }

    // A STATE_VIOLATION completion left the worker heap corrupt (cleanup was
    // skipped to avoid trapping). Stand up a fresh worker before the next
    // program so the corruption doesn't cascade into false signals.
    if (need_respawn) {
        if (RecoverFromWedge()) {
            ++stats_.wedge_recoveries;
        } else {
            ++stats_.wedge_recovery_failures;
            return false;
        }
    }

    // wedge_initial_drain_ms expired without terminal event for THIS
    // submit: candidate wedge. Verify on a fresh worker before
    // archiving. VerifyWedgeOnFresh handles its own counter updates and
    // a pre-replay health check.
    if (!saw) {
        const auto candidate_payload = mutated;
        const auto orig_seed_id = req.seed_id;
        if (!RecoverFromWedge()) {
            return false;
        }
        const bool reproduced =
            VerifyWedgeOnFresh(candidate_payload, orig_seed_id);
        if (reproduced) {
            RecordWedge(req.executor_id, orig_seed_id, candidate_payload);
            (void)RecoverFromWedge();
        }
    }

    stats_.corpus_current = store_.Size();
    return saw;
}

void XiuosFuzzSession::RecordWedge(std::uint64_t executor_id,
                                   std::uint64_t seed_id,
                                   const std::vector<std::uint8_t>& payload) {
    ++stats_.wedge_detections;
    const auto h = FnvHash64(payload);
    if (!wedge_dedup_.insert(h).second) {
        return;  // already persisted to transient bucket this session
    }
    const auto stem = HexHash(h);
    const auto c_src = DecodePayloadToC(payload, stem);

    // 每个 bug 一个子目录: wedge_<hash>/{program.bin, meta.json, repro.c}.
    auto write_finding_dir = [&](const std::filesystem::path& parent) {
        const auto dir = parent / ("wedge_" + stem);
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        {
            std::ofstream bin(dir / "program.bin", std::ios::binary);
            if (bin) {
                bin.write(reinterpret_cast<const char*>(payload.data()),
                          static_cast<std::streamsize>(payload.size()));
            }
        }
        {
            std::ofstream meta(dir / "meta.json");
            if (meta) {
                meta << "{\n"
                     << "  \"kind\": \"wedge\",\n"
                     << "  \"payload_hash\": \"0x" << stem << "\",\n"
                     << "  \"payload_bytes\": " << payload.size() << ",\n"
                     << "  \"executor_id\": " << executor_id << ",\n"
                     << "  \"seed_id\": " << seed_id << ",\n"
                     << "  \"detected_after_ms\": "
                     << cfg_.wedge_initial_drain_ms << "\n"
                     << "}\n";
            }
        }
        {
            std::ofstream src(dir / "repro.c");
            if (src) {
                src << c_src;
            }
        }
    };

    write_finding_dir(cfg_.wedge_bucket_dir);
    ++stats_.wedge_persisted;

    // 跨 campaign 永久档案;findings_archive_dir 留空则跳过。
    if (!cfg_.findings_archive_dir.empty() &&
        archive_dedup_.insert(h).second) {
        write_finding_dir(cfg_.findings_archive_dir);
        ++stats_.findings_archived;
    }
}

// Shared archiver for the per-program-oracle signals. Mirrors RecordWedge's
// dir layout but parameterized by prefix/kind and gated by a per-kind dedup so
// a leak lead and a wedge of the same payload both survive. `detail_json` is a
// fragment of extra meta lines, each ending in ",\n".
void XiuosFuzzSession::ArchiveProgram(
        const char* subdir_prefix, const char* kind,
        std::uint64_t executor_id, std::uint64_t seed_id,
        const std::vector<std::uint8_t>& payload,
        const std::string& detail_json,
        std::unordered_set<std::uint64_t>& dedup,
        std::uint64_t& archived_counter) {
    const auto h = FnvHash64(payload);
    if (!dedup.insert(h).second) return;  // already archived this payload+kind
    const auto stem = HexHash(h);
    const auto c_src = DecodePayloadToC(payload, stem);

    auto write_dir = [&](const std::filesystem::path& parent) {
        const auto dir = parent / (std::string(subdir_prefix) + stem);
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        {
            std::ofstream bin(dir / "program.bin", std::ios::binary);
            if (bin) {
                bin.write(reinterpret_cast<const char*>(payload.data()),
                          static_cast<std::streamsize>(payload.size()));
            }
        }
        {
            std::ofstream meta(dir / "meta.json");
            if (meta) {
                meta << "{\n"
                     << "  \"kind\": \"" << kind << "\",\n"
                     << "  \"payload_hash\": \"0x" << stem << "\",\n"
                     << "  \"payload_bytes\": " << payload.size() << ",\n"
                     << "  \"executor_id\": " << executor_id << ",\n"
                     << "  \"seed_id\": " << seed_id << ",\n"
                     << detail_json
                     << "  \"schema\": 1\n"
                     << "}\n";
            }
        }
        {
            std::ofstream src(dir / "repro.c");
            if (src) src << c_src;
        }
    };

    if (!cfg_.wedge_bucket_dir.empty()) write_dir(cfg_.wedge_bucket_dir);
    if (!cfg_.findings_archive_dir.empty()) {
        write_dir(cfg_.findings_archive_dir);
        ++archived_counter;
    }
}

void XiuosFuzzSession::RecordStateViolation(
        std::uint64_t executor_id, std::uint64_t seed_id, std::int32_t code,
        const std::vector<std::uint8_t>& payload) {
    ++stats_.state_violations;
    const std::string detail =
        "  \"violation_code\": " + std::to_string(code) + ",\n";
    ArchiveProgram("statev_", "state_violation", executor_id, seed_id, payload,
                   detail, statev_dedup_, stats_.state_violations_archived);
}

void XiuosFuzzSession::RecordLeakLead(
        std::uint64_t executor_id, std::uint64_t seed_id,
        std::uint32_t leak_delta, const std::vector<std::uint8_t>& payload) {
    ++stats_.leak_leads;
    const std::string detail =
        "  \"leak_bytes\": " + std::to_string(leak_delta) + ",\n";
    ArchiveProgram("leak_", "leak_lead", executor_id, seed_id, payload,
                   detail, leak_dedup_, stats_.leak_leads_archived);
}

unsigned XiuosFuzzSession::RunLoop(unsigned iterations,
                                   unsigned progress_every,
                                   ProgressFn on_progress) {
    if (!booted_) return 0;
    unsigned attempted = 0;
    for (unsigned i = 1; i <= iterations; ++i) {
        (void)Step();
        ++attempted;
        if (progress_every > 0 && (i % progress_every) == 0 && on_progress) {
            on_progress(i, Snapshot());
        }
    }
    return attempted;
}

// ──────────────────────── v1 call-level oracle ──────────────────────────

namespace {

// Each oracle case = (name, payload, expected last_ret set).
//
// v1 model: payload is a fully FSM-valid lifecycle (or a deliberately-empty
// op-on-empty) whose last call has a clearly-defined kernel return
// contract. The case lists ALL legal aux values; anything outside is a
// finding written to <vm_workdir>/oracle/<case>.json.
//
// Skipped for v1 (per call-level-oracle plan):
//   - sem multi-waiter broadcast: can't observe from main task without
//     victim state inspection. v2 work.
//   - CalculateTickFromTimeMs(0): need to nail the contract first
//     ("0 ms == 0 ticks" vs "0 ms == MIN_TICKS") before we call kernel
//     behavior a bug.
struct OracleCase {
    const char* name;
    std::vector<refuzz::program::xiuos::XiuosProgramCall> calls;
    std::vector<int32_t> expected_aux;  // any of these matches
    const char* hypothesis;             // note for finding json
};

// Loads `oracle_contract` declarations from the descriptor JSON. Each
// API may carry e.g. `{ "on_success_aux": 0 }` or invariant entries like
// `{ "on_empty_events_timeout0_aux": [-2, -10] }`. The map is keyed by
// API name and stores the contract as raw JSON; specific accessors below
// translate to int32_t / vector<int32_t> as needed. This way the value
// "EOK = 0" lives in spec (descriptor.json), not in C++ literals — paper
// claim: oracle expectations come from the API contract, not from the
// fuzz author. Default path discoverable via XIUOS_DESCRIPTOR_PATH env;
// falls back to in-repo location for tests.
struct OracleContracts {
    std::unordered_map<std::string, nlohmann::json> by_api;
};

OracleContracts LoadOracleContracts() {
    const char* env_path = std::getenv("XIUOS_DESCRIPTOR_PATH");
    const std::string path = env_path && *env_path
        ? env_path
        : std::string("/workspace/talaria/tools/"
                      "xiuos_refuzz/descriptors/common_kernel_sem_mutex.json");
    OracleContracts out;
    std::ifstream f(path);
    if (!f) {
        // Spec missing → fall through with empty map; baseline cases that
        // look up by name will fail-loud during BuildOracleCaseTable.
        return out;
    }
    nlohmann::json root;
    try { f >> root; }
    catch (...) { return out; }
    if (!root.contains("apis") || !root["apis"].is_array()) return out;
    for (const auto& a : root["apis"]) {
        if (!a.contains("name") || !a.contains("oracle_contract")) continue;
        out.by_api[a["name"].get<std::string>()] = a["oracle_contract"];
    }
    return out;
}

// Look up `on_success_aux` from a loaded contracts map. Returns the
// expected aux as a single-element vector for OracleCase.expected_aux.
// If the API isn't in the spec, returns {0} as a safe default but logs
// to stderr so missing entries are visible during development.
std::vector<int32_t> SuccessAuxFor(
    const OracleContracts& sp, const char* api_name) {
    const auto it = sp.by_api.find(api_name);
    if (it == sp.by_api.end() || !it->second.contains("on_success_aux")) {
        std::fprintf(stderr,
            "WARN oracle_contract.on_success_aux missing for %s; "
            "falling back to {0}\n", api_name);
        return {0};
    }
    return {it->second["on_success_aux"].get<int32_t>()};
}

// Look up an invariant aux set (e.g. on_empty_events_timeout0_aux) and
// return it as a vector<int32_t>. Empty vector if missing.
std::vector<int32_t> InvariantAuxFor(
    const OracleContracts& sp, const char* api_name, const char* key) {
    const auto it = sp.by_api.find(api_name);
    if (it == sp.by_api.end() || !it->second.contains(key)) return {};
    std::vector<int32_t> out;
    const auto& v = it->second[key];
    if (v.is_number_integer()) out.push_back(v.get<int32_t>());
    else if (v.is_array()) {
        for (const auto& x : v) {
            if (x.is_number_integer()) out.push_back(x.get<int32_t>());
        }
    }
    return out;
}

std::vector<refuzz::program::xiuos::XiuosProgramCall>
MakeCalls(std::initializer_list<std::pair<refuzz::program::xiuos::XiuosApiId,
                                          std::vector<std::uint32_t>>> ops) {
    std::vector<refuzz::program::xiuos::XiuosProgramCall> out;
    for (auto& [api, args] : ops) {
        refuzz::program::xiuos::XiuosProgramCall c;
        c.api_id = api;
        c.argc   = static_cast<std::uint8_t>(args.size());
        for (std::size_t i = 0; i < args.size() && i < 4; ++i) c.args[i] = args[i];
        out.push_back(c);
    }
    return out;
}

// Declarative family spec for create-delete baselines: each entry says
// "this family's CREATE + DELETE pair must round-trip — expected aux is
// read from descriptor.apis.<DELETE_API>.oracle_contract.on_success_aux,
// NOT from a C++ literal." Adding a new family means adding one struct
// entry here + an entry in descriptor JSON.
struct CreateDeleteBaseline {
    const char*                       family;             // human label, slug
    refuzz::program::xiuos::XiuosApiId create_api;
    std::vector<std::uint32_t>        create_args;
    refuzz::program::xiuos::XiuosApiId delete_api;
    std::vector<std::uint32_t>        delete_args;
    const char*                       delete_api_name;    // for spec lookup
};

const std::vector<CreateDeleteBaseline>& KCreateDeleteBaselines() {
    using Api = refuzz::program::xiuos::XiuosApiId;
    static const std::vector<CreateDeleteBaseline> kTable = {
        {"sem",   Api::SemCreate,   {0u, 1u},     Api::SemDelete,   {0u}, "SEM_DELETE"},
        {"mutex", Api::MutexCreate, {0u},         Api::MutexDelete, {0u}, "MUTEX_DELETE"},
        {"msgq",  Api::MsgqCreate,  {0u, 0u, 0u}, Api::MsgqDelete,  {0u}, "MSGQ_DELETE"},
        {"event", Api::EventCreate, {0u, 1u},     Api::EventDelete, {0u}, "EVENT_DELETE"},
    };
    return kTable;
}

std::vector<OracleCase> BuildOracleCaseTable() {
    using Api = refuzz::program::xiuos::XiuosApiId;
    std::vector<OracleCase> t;

    // ── (e) Cold-boot probes (must run first, before any sem is created)
    // dq_init_first_call_cold_boot — submits DQ_INIT before the other
    // oracle cases. If kernel data_queue.c's InitDataqueue contains
    //   if (!sem_blank) break;
    // then a legal semaphore id 0 would be misclassified as ERROR. The
    // current virt-rv32 boot usually has sem id 0 already occupied before
    // this oracle runs, so this is a probe for the risk, not a guaranteed
    // failure. Order-sensitive — keep near the front.
    t.push_back({
        "dq_init_first_call_cold_boot",
        {refuzz::program::xiuos::XiuosProgramCall{}}, // placeholder, set below
        std::vector<int32_t>{0},
        "DQ_INIT must return EOK; -ERROR would witness a NONE=0 "
        "collision in data_queue.c InitDataqueue's `if(!sem_blank)` check."
    });
    {
        refuzz::program::xiuos::XiuosProgramCall c;
        c.api_id = Api::DqInit; c.argc = 2;
        c.args[0] = 0u; c.args[1] = 2u;  // slot 0, nc_idx=2 → NodeNumber=4
        t.back().calls = {c};
    }
    // Note: a DQ_PUSH-past-capacity probe was useful during DQ wire bring-up
    // (confirmed PushDataqueue WAITING_FOREVER actually blocks the caller
    // task as kernel spec claims). Removed from the default oracle suite
    // because including it wedges the oracle's same-worker fixture and
    // cascades subsequent cases. To re-enable for diagnostics, add back
    // a case with calls {DqInit(0,1), DqPush(0,0,0), DqPush(0,0,0)} and
    // recover the worker after RunOracleSelfTest.

    // Load expected-aux values from descriptor spec (one-time at first call).
    // All expected_aux assignments below read from `oc` — no C++ literal for
    // expected values, even for known bugs (Classes D / E).
    static const OracleContracts oc = LoadOracleContracts();

    // Lifetime-stable storage for generated case names + hypotheses (deque
    // keeps element pointers valid across push_back, unlike vector).
    static std::deque<std::string> kBaselineNames;
    static std::deque<std::string> kBaselineHyps;

    // ── (a) Mechanically derived baselines ────────────────────────────
    // Generated by iterating KCreateDeleteBaselines(). Expected aux comes
    // from descriptor `oracle_contract.on_success_aux`; the baseline
    // table contributes only program SHAPE (CREATE→DELETE), not values.
    for (const auto& b : KCreateDeleteBaselines()) {
        kBaselineNames.emplace_back(std::string(b.family) +
                                    "_create_delete_returns_eok");
        kBaselineHyps.emplace_back("Baseline: " + std::string(b.family) +
                                   " DELETE on live slot — expected_aux "
                                   "from descriptor oracle_contract.");
        t.push_back({
            kBaselineNames.back().c_str(),
            MakeCalls({
                {b.create_api, b.create_args},
                {b.delete_api, b.delete_args},
            }),
            SuccessAuxFor(oc, b.delete_api_name),
            kBaselineHyps.back().c_str(),
        });
    }

    // ── (b) Declarative invariants (spec contracts) ───────────────────
    // EVENT_PROCESS on a valid event with timeout=0 and no triggered bits
    // must return -ETIMEOUT (event.c:176-177). Both program shape and
    // expected aux set come from descriptor (oracle_contract keys
    // on_empty_events_timeout0_aux / on_empty_slot_aux).
    t.push_back({
        "event_process_empty_timeout0_returns_etimeout",
        MakeCalls({
            {Api::EventCreate,  {0u, 1u}},
            {Api::EventProcess, {0u, 0u, 0u}},
        }),
        InvariantAuxFor(oc, "EVENT_PROCESS", "on_empty_events_timeout0_aux"),
        "EVENT_PROCESS on a valid event with no triggered bits and "
        "timeout 0 must return -ETIMEOUT (event.c:176)."
    });
    t.push_back({
        "event_process_empty_slot_returns_minus_error",
        MakeCalls({
            {Api::EventProcess, {0u, 0u, 0u}},
        }),
        InvariantAuxFor(oc, "EVENT_PROCESS", "on_empty_slot_aux"),
        "EVENT_PROCESS on empty slot: worker returns -ERROR before kernel."
    });

    // ── (c) Known-bug regression markers ──────────────────────────────
    // These are regression markers for bugs already discovered via wedge
    // oracle / source audit. Paper note: NOT claimed as "discovered by
    // oracle"; they are claimed as "regression protection with expected
    // aux still derived from spec (descriptor.oracle_contract)".

    // Class D — WorkSubmit_immediate has no `return EOK;` on success
    // path (workqueue.c:115-136). Expected aux comes from
    // descriptor.WQ_SUBMIT.oracle_contract (=0 per kernel signature).
    t.push_back({
        "wq_submit_immediate_returns_eok",
        MakeCalls({
            {Api::WqCreate, {0u, 0u}},
            {Api::WqSubmit, {0u}},
        }),
        SuccessAuxFor(oc, "WQ_SUBMIT"),
        "WorkSubmit_immediate has no `return EOK;` on success path."
    });
    // Class E — KCreateTimer returns legal id=0 but WorkSubmit compares
    // it with NONE=0 → false -ERROR. Expected aux from descriptor.
    t.push_back({
        "wq_submit_delayed_returns_eok",
        MakeCalls({
            {Api::WqCreate,        {0u, 0u}},
            {Api::WqSubmitDelayed, {0u, 2u}},
        }),
        SuccessAuxFor(oc, "WQ_SUBMIT_DELAYED"),
        "KCreateTimer returns legal timer id 0, but WorkSubmit compares "
        "that id with NONE=0 and returns -ERROR. Expected delayed submit "
        "success (EOK); caught by call-level oracle."
    });

    // ── (d) Hypothesis probes ─────────────────────────────────────────
    // KTaskPrioSet (mutex.c:116 "bugged" comment). Probe whether random
    // mutator reaches the bug. Expected aux from descriptor.
    t.push_back({
        "task_prio_set_on_blocked_victim_returns_eok",
        MakeCalls({
            {Api::SemCreate,         {0u, 0u}},
            {Api::TaskSpawnBlockSem, {0u, 0u}},
            {Api::TaskPrioSet,       {0u, 1u}},
        }),
        SuccessAuxFor(oc, "TASK_PRIO_SET"),
        "KTaskPrioSet on a valid blocked victim; kernel admits this API "
        "is bugged (mutex.c:116). Probe for random-mutator reachability."
    });

    // DQ_INIT probe — checks the same NONE=0 risk shape in data_queue.c:
    //   p_queue->sem_blank = KSemaphoreCreate(...);
    //   if (!p_queue->sem_blank) break;   // sem_id == 0 misclassified as ERROR
    // Same risk shape as Class E (KCreateTimer / WorkSubmit), but current
    // default virt-rv32 boot does not consistently allocate sem id 0 here.
    // Expected EOK; a failure would be the witness.
    t.push_back({
        "dq_init_returns_eok_probe",
        MakeCalls({{Api::DqInit, {0u, 2u}}}),  // slot 0, nc_idx=2 → NodeNumber=4
        SuccessAuxFor(oc, "DQ_INIT"),
        "Probe: DQ_INIT should return EOK; -ERROR would witness a NONE=0 "
        "sem id collision in data_queue.c InitDataqueue."
    });

    // ── (f) Resource watermark oracle ─────────────────────────────────
    // RESOURCE_SNAPSHOT is not a kernel API under fuzz; it is a worker
    // introspection endpoint whose aux must be 0 after a scenario that
    // should leave no live waiter/resource state. This turns silent leaks
    // and dangling-list nodes into call-level oracle findings instead of
    // relying on a later wedge.
    //
    // Baselines first: each must read aux==0, proving the snapshot
    // measurement is sound (not a constant non-zero). Without these the
    // leak case below could not be distinguished from a measurement
    // artifact. They run before the leak case so any contamination of the
    // snapshot path shows up here, not as a false leak.
    t.push_back({
        "watermark_baseline_empty_program_zero",
        MakeCalls({{Api::ResourceSnapshot, {}}}),
        std::vector<int32_t>{0},
        "Empty program then RESOURCE_SNAPSHOT: no waitqueue nodes, no live "
        "victim slots; aux must be 0. Validates the snapshot reads 0 when "
        "clean."
    });
    t.push_back({
        "watermark_baseline_waitq_init_only_zero",
        MakeCalls({
            {Api::WaitqInit,        {0u}},
            {Api::ResourceSnapshot, {}},
        }),
        std::vector<int32_t>{0},
        "WaitqInit with no waiter then snapshot: block_threads_list empty; "
        "aux must be 0."
    });
    t.push_back({
        "watermark_baseline_sem_lifecycle_zero",
        MakeCalls({
            {Api::SemCreate,        {0u, 0u}},
            {Api::SemDelete,        {0u}},
            {Api::ResourceSnapshot, {}},
        }),
        std::vector<int32_t>{0},
        "Sem create+delete then snapshot: no waitqueue/task residue; aux "
        "must be 0."
    });
    t.push_back({
        "watermark_baseline_dq_lifecycle_zero",
        MakeCalls({
            {Api::DqInit,           {0u, 2u}},
            {Api::DqDeinit,         {0u}},
            {Api::ResourceSnapshot, {}},
        }),
        std::vector<int32_t>{0},
        "Dataqueue init+deinit then snapshot: no waitqueue/task residue; "
        "aux must be 0."
    });
    // NOTE: a `watermark_baseline_waitq_wake_clean_zero` case
    // (WaitqInit + SpawnWait + Wake + Terminate + Snapshot) was tried as a
    // "clean wake" contrast baseline but is NOT clean: after WAITQ_WAKE the
    // high-priority victim runs RefuzzVictimSleepForever, whose
    // MdelayKTask(10) re-arms a delay node; TASK_TERMINATE then deletes the
    // victim and _KTaskResourceDelete leaves that delay node dangling in
    // xiaoshan_delay_head (the Class F gap). ~100ms later the timer-tick
    // handler traverses the dangling node and wedges. It looks fine
    // standalone only because the program completes (~48ms) before the
    // node's deadline. So the wake+terminate path is itself a Class F
    // manifestation, not a baseline — kept out of the must-pass set. A
    // dedicated reproducer for it is future work.
    t.push_back({
        "waitq_delete_waiter_leaves_no_resource_watermark",
        MakeCalls({
            {Api::WaitqInit,        {0u}},
            {Api::WaitqSpawnWait,   {0u, 0u, 3u}},
            {Api::SemCreate,        {0u, 0u}},
            {Api::SemObtain,        {0u, 2u}},
            {Api::TaskTerminate,    {0u}},
            {Api::ResourceSnapshot, {}},
        }),
        SuccessAuxFor(oc, "RESOURCE_SNAPSHOT"),
        "A victim deleted while blocked in WqueueWait must not leave a "
        "waitqueue node or live victim slot. RESOURCE_SNAPSHOT aux encodes "
        "pending waitqueue nodes in bits 0..7 and live victim slots in "
        "bits 8..15; clean baseline is 0."
    });

    // ── (g) Waitqueue leak escalation (targeted, not random) ──────────
    // Step 1 — prove the leak ACCUMULATES (unbounded), not incidental.
    // Repeat SPAWN_WAIT→TERMINATE on the SAME queue WITHOUT re-INIT (a
    // re-INIT would reset block_threads_list and orphan prior nodes out of
    // the count). Each cycle's victim enters WqueueWait (adds a pin_node),
    // then is deleted while waiting, leaving the node. aux low byte should
    // equal the cycle count. Expected 0 (clean); the dumped actual aux is
    // the leak magnitude — N growing with cycle count proves unbounded.
    // Each cycle needs a YIELD (SemObtain on an empty sem, ~1 tick) after
    // SPAWN_WAIT so the high-priority victim actually runs WqueueWait and
    // enters block_threads_list before TERMINATE deletes it. Without the
    // yield the victim never runs (StartupKTask does not preempt the worker
    // here) and no node is added — which is exactly why the no-yield
    // version measured aux=0.
    {
        using Call = refuzz::program::xiuos::XiuosProgramCall;
        auto mk = [](Api a, std::vector<std::uint32_t> args) {
            Call c; c.api_id = a; c.argc = (std::uint8_t)args.size();
            for (std::size_t i = 0; i < args.size() && i < 4; ++i) c.args[i] = args[i];
            return c;
        };
        for (int cycles : {2, 4}) {
            std::vector<Call> calls;
            calls.push_back(mk(Api::WaitqInit, {0u}));
            calls.push_back(mk(Api::SemCreate, {0u, 0u}));  // empty sem to yield on
            for (int i = 0; i < cycles; ++i) {
                calls.push_back(mk(Api::WaitqSpawnWait, {0u, 0u, 3u}));
                calls.push_back(mk(Api::SemObtain, {0u, 2u}));   // yield ~1 tick
                calls.push_back(mk(Api::TaskTerminate, {0u}));
            }
            calls.push_back(mk(Api::ResourceSnapshot, {}));
            t.push_back({
                cycles == 2 ? "waitq_leak_accumulates_2cycles"
                            : "waitq_leak_accumulates_4cycles",
                std::move(calls),
                std::vector<int32_t>{0},
                "Repeated SPAWN_WAIT→yield→TERMINATE on one queue without "
                "re-INIT. Clean expectation is aux=0; the dumped actual aux "
                "equals the number of stale waitqueue nodes left behind. "
                "Growth with cycle count witnesses an UNBOUNDED waiter-node "
                "leak."
            });
        }
    }

    // Step 2 — try to ESCALATE the stale node into a fault. After a waiter
    // is deleted (stale node remains), WAKE traverses block_threads_list
    // and dereferences node->polling_task (the freed victim descriptor).
    // If the descriptor was recycled / freed, this is a UAF / wrong-wakeup
    // / list-corruption. WAITQ_WAKE now passes a non-null key so we test
    // the traversal, not a worker param error. saw_terminal=false here =
    // the escalation fired (wedge); a clean terminal with aux means the
    // kernel tolerated it (descriptor still mapped).
    t.push_back({
        "waitq_wake_after_delete_waiter_escalation_probe",
        MakeCalls({
            {Api::WaitqInit,        {0u}},
            {Api::WaitqSpawnWait,   {0u, 0u, 3u}},
            {Api::SemCreate,        {0u, 0u}},
            {Api::SemObtain,        {0u, 2u}},   // yield: victim enters WqueueWait
            {Api::TaskTerminate,    {0u}},       // delete waiter → stale node
            {Api::WaitqWake,        {0u}},       // traverse stale node → deref freed victim
            {Api::ResourceSnapshot, {}},
        }),
        std::vector<int32_t>{0},
        "Delete a blocked waiter (leaves stale node), then WAKE traverses "
        "it and dereferences the freed victim descriptor. Probe for "
        "escalation of the leak into a fault/UAF. saw_terminal=false here "
        "means the escalation fired."
    });

    // Step 3: delay-list watermark (Class F, distinct from waitqueue).
    // A finite-timeout blocker that calls KTaskSetDelay LAST (after
    // suspending) stays in xiaoshan_delay_head. _DelayKTask (MdelayKTask)
    // and _SemaphoreObtain's finite-timeout path both do this. Deleting
    // such a task leaves a dangling delay node because _KTaskResourceDelete
    // never calls KTaskUnSetDelay. RESOURCE_SNAPSHOT now counts
    // xiaoshan_delay_head in bits 16..23 (clean baseline 0, validated by
    // the watermark baselines above which all read 0 there).
    //
    // SELF_DELAY victim does MdelayKTask(200ms) then sleeps; we yield
    // (1 tick) so it enters the delay list, then delete it WHILE delayed. The
    // 200ms deadline is far past the program's ~50ms runtime, so the
    // dangling node does NOT expire mid-program (which would wedge) — it
    // sits in the list for the snapshot to count. Expected 0; the dumped
    // actual aux's bits 16..23 are the leaked-delay-node count.
    t.push_back({
        "self_delay_delete_leaves_delay_list_node",
        MakeCalls({
            {Api::TaskSpawnSelfDelay, {0u, 3u}},  // task0, ms_idx=3: 200ms
            {Api::SemCreate,          {0u, 0u}},
            {Api::SemObtain,          {0u, 2u}},   // yield ~1 tick; victim enters MdelayKTask
            {Api::TaskTerminate,      {0u}},       // delete while delayed: Class F delay-node leak
            {Api::ResourceSnapshot,   {}},
        }),
        std::vector<int32_t>{0},
        "Delete a task blocked in MdelayKTask (finite delay): "
        "_KTaskResourceDelete skips KTaskUnSetDelay, leaving a dangling "
        "node in xiaoshan_delay_head. RESOURCE_SNAPSHOT bits 16..23 count "
        "it; clean is 0, non-zero witnesses the Class F delay-list leak."
    });

    // Lateral coverage of the Class F root cause: prove the delay-node leak
    // is NOT specific to MdelayKTask but common to every suspend->
    // KTaskSetDelay blocker. A finite-timeout KSemaphoreObtain registers a
    // delay node (LinklistSuspend first, KTaskSetDelay last; node stays);
    // deleting the blocked waiter leaves it dangling. Victim blocks on sem
    // slot 0; the worker yields on sem slot 1 so the (low-prio) victim runs
    // and enters the obtain before TERMINATE. Expected aux=0; vulnerable
    // kernel reads delay=1 (bits 16..23).
    t.push_back({
        "finite_timeout_sem_waiter_delete_leaves_delay_node",
        MakeCalls({
            {Api::SemCreate,                 {0u, 0u}},     // victim target sem (empty)
            {Api::SemCreate,                 {1u, 0u}},     // worker yield sem (empty)
            {Api::TaskSpawnBlockSemTimeout,  {0u, 0u, 2u}}, // victim: obtain sem0, 200ms
            {Api::SemObtain,                 {1u, 2u}},     // worker yields ~1 tick; victim enters obtain
            {Api::TaskTerminate,             {0u}},          // delete blocked waiter; delay-node leak
            {Api::ResourceSnapshot,          {}},
        }),
        std::vector<int32_t>{0},
        "Finite-timeout KSemaphoreObtain waiter deleted while blocked: like "
        "MdelayKTask, _SemaphoreObtain registers KTaskSetDelay last, so the "
        "delay node survives the suspend and is leaked on delete "
        "(_KTaskResourceDelete gap). RESOURCE_SNAPSHOT bits 16..23 count it; "
        "non-zero = Class F generalizes beyond MdelayKTask."
    });

    // Same lateral coverage for KEventProcess and KMsgQueueRecv finite-
    // timeout waiters. Both block via LinklistSuspend then KTaskSetDelay
    // (delay node last → stays); a victim deleted while blocked leaks it.
    // Expected aux=0; vulnerable kernel reads delay=1 (bits 16..23).
    t.push_back({
        "finite_timeout_event_waiter_delete_leaves_delay_node",
        MakeCalls({
            {Api::EventCreate,                {0u, 0u}},     // victim target event
            {Api::SemCreate,                  {1u, 0u}},     // worker yield sem (empty)
            {Api::TaskSpawnBlockEventTimeout, {0u, 0u, 2u}}, // victim: KEventProcess, 200ms
            {Api::SemObtain,                  {1u, 2u}},     // worker yields → victim enters process
            {Api::TaskTerminate,              {0u}},          // delete blocked waiter → delay leak
            {Api::ResourceSnapshot,           {}},
        }),
        std::vector<int32_t>{0},
        "Finite-timeout KEventProcess waiter deleted while blocked leaves a "
        "dangling delay node (Class F). bits 16..23 count it; non-zero "
        "witnesses the leak."
    });
    t.push_back({
        "finite_timeout_msgq_waiter_delete_leaves_delay_node",
        MakeCalls({
            {Api::MsgqCreate,                    {0u, 0u, 0u}}, // victim target msgq
            {Api::SemCreate,                     {1u, 0u}},     // worker yield sem (empty)
            {Api::TaskSpawnBlockMsgqRecvTimeout, {0u, 0u, 2u}}, // victim: KMsgQueueRecv, 200ms
            {Api::SemObtain,                     {1u, 2u}},     // worker yields → victim enters recv
            {Api::TaskTerminate,                 {0u}},          // delete blocked waiter → delay leak
            {Api::ResourceSnapshot,              {}},
        }),
        std::vector<int32_t>{0},
        "Finite-timeout KMsgQueueRecv waiter deleted while blocked leaves a "
        "dangling delay node (Class F). bits 16..23 count it; non-zero "
        "witnesses the leak."
    });
    // Mutex completes the finite-timeout blocker matrix. Unlike the others,
    // a mutex only blocks if already HELD: the main worker obtains it first
    // (uncontended → immediate), then the victim's finite-timeout
    // KMutexObtain contends, suspends, and KTaskSetDelay-last leaves a delay
    // node. Deleting the blocked victim leaks it. Expected aux=0; vulnerable
    // kernel reads delay=1.
    t.push_back({
        "finite_timeout_mutex_waiter_delete_leaves_delay_node",
        MakeCalls({
            {Api::MutexCreate,                {0u}},          // mutex slot 0
            {Api::MutexObtain,                {0u, 0u}},      // worker becomes holder (uncontended)
            {Api::SemCreate,                  {1u, 0u}},      // worker yield sem (empty)
            {Api::TaskSpawnBlockMutexTimeout, {0u, 0u, 2u}},  // victim: contend mutex0, 200ms
            {Api::SemObtain,                  {1u, 2u}},      // worker yields → victim blocks on mutex
            {Api::TaskTerminate,              {0u}},           // delete blocked waiter → delay leak
            {Api::ResourceSnapshot,           {}},
        }),
        std::vector<int32_t>{0},
        "Finite-timeout KMutexObtain waiter (contending a worker-held mutex) "
        "deleted while blocked leaves a dangling delay node (Class F). Same "
        "_KTaskResourceDelete cleanup gap; completes the sem/event/msgq/"
        "mutex + MdelayKTask matrix. bits 16..23 count it."
    });
    // 6th finite-timeout blocker: gatherblock AllocBlockMemGather. Requires
    // CONFIG_KERNEL_MEMBLOCK (config-expanded). Exhaust a 1-block pool, then
    // a victim's finite-timeout AllocBlockMemGather blocks on the pool's
    // wait_task (SuspendKTask + KTaskSetDelay-last). Deleting it leaks the
    // delay node — Class F generalizes to gatherblock too. (The pool's
    // wait_task ALSO gets a dangling sched_link, but RESOURCE_SNAPSHOT only
    // counts the delay-list; that wait_task corruption is a separate
    // source-audit lead, not measured here.)
    t.push_back({
        "finite_timeout_gb_alloc_waiter_delete_leaves_delay_node",
        MakeCalls({
            {Api::GbCreate,              {0u, 2u, 1u}},  // pool0: 1 block of 32B
            {Api::GbAlloc,               {0u, 0u, 1u}},  // exhaust (take the 1 block)
            {Api::SemCreate,             {1u, 0u}},       // worker yield sem
            {Api::TaskSpawnBlockGbAlloc, {0u, 0u, 2u}},   // victim: alloc pool0, 200ms → blocks on wait_task
            {Api::SemObtain,             {1u, 2u}},       // worker yields → victim enters AllocBlockMemGather
            {Api::TaskTerminate,         {0u}},            // delete blocked waiter → delay-node leak
            {Api::ResourceSnapshot,      {}},
        }),
        std::vector<int32_t>{0},
        "Finite-timeout AllocBlockMemGather waiter (pool exhausted) deleted "
        "while blocked leaves a dangling delay node (Class F #6, gatherblock; "
        "needs CONFIG_KERNEL_MEMBLOCK). bits 16..23 count it."
    });

    // ── (g2) WAITING_FOREVER timeout-contract impact (tick.c overflow) ──
    // Same victim setup as the finite Class F cases but timeout_idx=3 =
    // WAITING_FOREVER. A blocker that special-cases WAITING_FOREVER before
    // CalculateTickFromTimeMs (KSemaphoreObtain, KMsgQueueSend) suspends with
    // NO KTaskSetDelay -> after deleting the waiter, delay count stays 0. A
    // blocker that does NOT guard it (KMutexObtain / KEventProcess /
    // KMsgQueueRecv / AllocBlockMemGather) feeds -1 (0xFFFFFFFF) into
    // CalculateTickFromTimeMs, which overflows the uint32 multiply to a finite
    // ~4294967-tick (~11.9h) timeout, so wait_time>0 and KTaskSetDelay IS
    // called -> the deleted waiter leaks a delay node (delay=1). Expected
    // aux=0 for ALL (a correct kernel honors WAITING_FOREVER); the sem case is
    // the positive control that PASSES, the others FAIL with aux=65536,
    // pinning the per-API impact of the tick overflow at the API level.
    t.push_back({
        "waiting_forever_sem_waiter_honored_no_delay_node",
        MakeCalls({
            {Api::SemCreate,                 {0u, 0u}},
            {Api::SemCreate,                 {1u, 0u}},
            {Api::TaskSpawnBlockSemTimeout,  {0u, 0u, 3u}}, // WAITING_FOREVER
            {Api::SemObtain,                 {1u, 2u}},
            {Api::TaskTerminate,             {0u}},
            {Api::ResourceSnapshot,          {}},
        }),
        std::vector<int32_t>{0},
        "CONTROL: KSemaphoreObtain guards `WAITING_FOREVER == msec` before "
        "CalculateTickFromTimeMs, so wait_time = WAITING_FOREVER (<=0) and "
        "KTaskSetDelay is skipped (semaphore.c `if (wait_time > 0)`). Deleting "
        "the forever-blocked waiter leaves NO delay node -> aux 0. PASS proves "
        "the oracle distinguishes honored WAITING_FOREVER from the finite leak."
    });
    t.push_back({
        "waiting_forever_mutex_waiter_registers_garbage_delay",
        MakeCalls({
            {Api::MutexCreate,                {0u}},
            {Api::MutexObtain,                {0u, 0u}},
            {Api::SemCreate,                  {1u, 0u}},
            {Api::TaskSpawnBlockMutexTimeout, {0u, 0u, 3u}}, // WAITING_FOREVER
            {Api::SemObtain,                  {1u, 2u}},
            {Api::TaskTerminate,              {0u}},
            {Api::ResourceSnapshot,           {}},
        }),
        std::vector<int32_t>{0},
        "FINDING: KMutexObtain has NO `WAITING_FOREVER == msec` guard "
        "(mutex.c: wait_time = CalculateTickFromTimeMs(msec) directly), so "
        "WAITING_FOREVER overflows to a finite ~4294967-tick timeout and "
        "KTaskSetDelay registers a (garbage) delay node. Expected 0 (honor "
        "WAITING_FOREVER); affected kernel reads delay=1 (aux 65536)."
    });
    t.push_back({
        "waiting_forever_event_waiter_registers_garbage_delay",
        MakeCalls({
            {Api::EventCreate,                {0u, 0u}},
            {Api::SemCreate,                  {1u, 0u}},
            {Api::TaskSpawnBlockEventTimeout, {0u, 0u, 3u}}, // WAITING_FOREVER
            {Api::SemObtain,                  {1u, 2u}},
            {Api::TaskTerminate,              {0u}},
            {Api::ResourceSnapshot,           {}},
        }),
        std::vector<int32_t>{0},
        "FINDING: KEventProcess has no WAITING_FOREVER guard (event.c: "
        "timeout = CalculateTickFromTimeMs(msec) directly) -> WAITING_FOREVER "
        "becomes a finite garbage timeout and registers a delay node. Expected "
        "0; affected kernel reads delay=1 (aux 65536)."
    });
    t.push_back({
        "waiting_forever_msgq_recv_waiter_registers_garbage_delay",
        MakeCalls({
            {Api::MsgqCreate,                    {0u, 0u, 0u}},
            {Api::SemCreate,                     {1u, 0u}},
            {Api::TaskSpawnBlockMsgqRecvTimeout, {0u, 0u, 3u}}, // WAITING_FOREVER
            {Api::SemObtain,                     {1u, 2u}},
            {Api::TaskTerminate,                 {0u}},
            {Api::ResourceSnapshot,              {}},
        }),
        std::vector<int32_t>{0},
        "FINDING: KMsgQueueRecv has no WAITING_FOREVER guard (msgqueue.c recv: "
        "timeout = CalculateTickFromTimeMs(msec) directly), unlike the SEND "
        "path which IS guarded. WAITING_FOREVER -> finite garbage timeout -> "
        "delay node. Expected 0; affected kernel reads delay=1 (aux 65536)."
    });
    // CONTROL / runtime confirmation of TC-1's send-side: a WAITING_FOREVER
    // *sender* blocked on a full queue is honored (msgqueue.c:104 guards the
    // sentinel before CalculateTickFromTimeMs), so no KTaskSetDelay → deleting
    // it leaves delay=0. Direct contrast with the recv case above (delay=1).
    t.push_back({
        "waiting_forever_msgq_send_waiter_honored_no_delay_node",
        MakeCalls({
            {Api::MsgqCreate,                    {0u, 0u, 0u}}, // each_len=4, max_msgs=1
            {Api::MsgqSend,                      {0u, 0u}},     // worker fills the 1 slot
            {Api::SemCreate,                     {1u, 0u}},
            {Api::TaskSpawnBlockMsgqSendTimeout, {0u, 0u, 3u}}, // victim: send WAITING_FOREVER on full queue
            {Api::SemObtain,                     {1u, 2u}},     // yield → victim blocks in send
            {Api::TaskTerminate,                 {0u}},          // delete blocked sender
            {Api::ResourceSnapshot,              {}},
        }),
        std::vector<int32_t>{0},
        "CONTROL: KMsgQueueSend(... WAITING_FOREVER) blocked on a full queue is "
        "honored — _MsgQueueSend special-cases WAITING_FOREVER (msgqueue.c:104) "
        "so wait_time<=0 and KTaskSetDelay is skipped. Deleting the forever-"
        "blocked sender leaves NO delay node -> aux 0. PASS confirms TC-1's "
        "send-side guard at runtime (contrast: the recv WAITING_FOREVER case "
        "leaks delay=1 because recv is unguarded)."
    });
    // FINDING (Class F, send-side): a FINITE-timeout sender blocked on a full
    // queue DOES register a delay node (KTaskSetDelay), so deleting it leaks it.
    t.push_back({
        "finite_timeout_msgq_send_waiter_delete_leaves_delay_node",
        MakeCalls({
            {Api::MsgqCreate,                    {0u, 0u, 0u}},
            {Api::MsgqSend,                      {0u, 0u}},     // fill
            {Api::SemCreate,                     {1u, 0u}},
            {Api::TaskSpawnBlockMsgqSendTimeout, {0u, 0u, 2u}}, // victim: send, 200ms finite
            {Api::SemObtain,                     {1u, 2u}},
            {Api::TaskTerminate,                 {0u}},          // delete blocked sender → delay leak
            {Api::ResourceSnapshot,              {}},
        }),
        std::vector<int32_t>{0},
        "FINDING (Class F, send-side): finite-timeout KMsgQueueSendwait blocked "
        "on a full queue suspends then KTaskSetDelay-last; deleting the blocked "
        "sender leaves the dangling delay node. Expected 0; vulnerable kernel "
        "reads delay=1 (aux 65536). Class F now spans recv- AND send-side msgq "
        "blocking."
    });
    t.push_back({
        "waiting_forever_gb_alloc_waiter_registers_garbage_delay",
        MakeCalls({
            {Api::GbCreate,              {0u, 2u, 1u}},
            {Api::GbAlloc,               {0u, 0u, 1u}},
            {Api::SemCreate,             {1u, 0u}},
            {Api::TaskSpawnBlockGbAlloc, {0u, 0u, 3u}}, // gb_timeout_idx 3 = WAITING_FOREVER
            {Api::SemObtain,             {1u, 2u}},
            {Api::TaskTerminate,         {0u}},
            {Api::ResourceSnapshot,      {}},
        }),
        std::vector<int32_t>{0},
        "FINDING: AllocBlockMemGather has no WAITING_FOREVER guard "
        "(gatherblock.c: wait_time = CalculateTickFromTimeMs(msec) directly; "
        "needs CONFIG_KERNEL_MEMBLOCK) -> WAITING_FOREVER becomes a finite "
        "garbage timeout -> delay node. Expected 0; affected reads delay=1."
    });

    // ── (h) Heap watermark ─────────────────────────────────────────────
    // HEAP_SNAPSHOT returns (used - per-program baseline). A program that
    // creates AND destroys everything it touches must net delta 0; a
    // positive delta after the destroy path ran witnesses un-reclaimed
    // heap. Baselines first (must read 0) to prove the measurement is sound
    // and tolerance is right; probes after.
    t.push_back({
        "heap_baseline_empty_zero",
        MakeCalls({{Api::HeapSnapshot, {}}}),
        std::vector<int32_t>{0},
        "Empty program then HEAP_SNAPSHOT: no allocations; delta must be 0."
    });
    t.push_back({
        "heap_baseline_malloc_free_zero",
        MakeCalls({
            {Api::Malloc,       {0u, 2u}},   // 64 bytes
            {Api::Free,         {0u}},
            {Api::HeapSnapshot, {}},
        }),
        std::vector<int32_t>{0},
        "malloc+free balanced: delta must be 0."
    });
    t.push_back({
        "heap_baseline_calloc_free_zero",
        MakeCalls({
            {Api::Calloc,       {0u, 2u, 1u}},  // 4 * 16
            {Api::Free,         {0u}},
            {Api::HeapSnapshot, {}},
        }),
        std::vector<int32_t>{0},
        "calloc+free balanced: delta must be 0."
    });
    t.push_back({
        "heap_baseline_realloc_free_zero",
        MakeCalls({
            {Api::Malloc,       {0u, 1u}},   // 16
            {Api::Realloc,      {0u, 3u}},   // grow to 256
            {Api::Free,         {0u}},
            {Api::HeapSnapshot, {}},
        }),
        std::vector<int32_t>{0},
        "malloc+realloc+free balanced: delta must be 0."
    });

    // Probes: create+destroy an object, then snapshot. delta>0 = the destroy
    // path left heap behind (lifetime leak).
    t.push_back({
        "heap_probe_msgq_create_delete_zero",
        MakeCalls({
            {Api::MsgqCreate,   {0u, 0u, 0u}},
            {Api::MsgqDelete,   {0u}},
            {Api::HeapSnapshot, {}},
        }),
        std::vector<int32_t>{0},
        "msgq create+delete: delta must be 0 if KDeleteMsgQueue frees the "
        "struct + msg_buf. Non-zero witnesses a msgq teardown heap leak."
    });
    t.push_back({
        "heap_probe_wq_submit_delayed_zero",
        MakeCalls({
            {Api::WqCreate,        {0u, 0u}},
            {Api::WqSubmitDelayed, {0u, 0u}},  // creates an internal timer (param)
            {Api::WqDeinit,        {0u}},
            {Api::HeapSnapshot,    {}},
        }),
        std::vector<int32_t>{0},
        "WorkSubmit delayed creates an internal timer/param; after WQ_DEINIT "
        "the heap should return to baseline. Non-zero delta witnesses a "
        "delayed-submit timer/param leak (the known NONE=0 path's lead)."
    });
    // Accumulation: each WQ_SUBMIT_DELAYED does WorkSubmit(time>0), which
    // x_mallocs a fresh WorkTimerParamType (+ internal softtimer); WQ_DEINIT
    // cancels none of them. So N delayed submits leak ~N * per-submit bytes —
    // proving LL-003 is an unbounded accumulating leak, not a one-off. Expected
    // 0; the FAIL deltas scale ~linearly with N (1x≈104, 2x≈208, 3x≈312).
    t.push_back({
        "heap_wq_submit_delayed_leak_accumulates_2x",
        MakeCalls({
            {Api::WqCreate,        {0u, 0u}},
            {Api::WqSubmitDelayed, {0u, 0u}},
            {Api::WqSubmitDelayed, {0u, 0u}},
            {Api::WqDeinit,        {0u}},
            {Api::HeapSnapshot,    {}},
        }),
        std::vector<int32_t>{0},
        "LL-003 accumulation (2x): two delayed submits leak ~2x the per-submit "
        "param/timer. Expected 0; delta ~= 2 * the 1x leak, proving it scales."
    });
    t.push_back({
        "heap_wq_submit_delayed_leak_accumulates_3x",
        MakeCalls({
            {Api::WqCreate,        {0u, 0u}},
            {Api::WqSubmitDelayed, {0u, 0u}},
            {Api::WqSubmitDelayed, {0u, 0u}},
            {Api::WqSubmitDelayed, {0u, 0u}},
            {Api::WqDeinit,        {0u}},
            {Api::HeapSnapshot,    {}},
        }),
        std::vector<int32_t>{0},
        "LL-003 accumulation (3x): delta ~= 3 * the 1x leak. The linear scaling "
        "across 1x/2x/3x is the unbounded-leak signal (soft -> hard evidence "
        "without needing the orphan-timer UAF to fire)."
    });

    // Sweep every synchronous-teardown family's create+delete pair through
    // the heap watermark. Each must net delta 0; a non-zero delta is a
    // teardown leak lead (same shape as WorkSubmit-delayed). Task family is
    // intentionally excluded — its descriptor reclaim is async via
    // zombie-recycle, so a snapshot right after TERMINATE is noisy.
    struct HeapTeardownProbe {
        const char* name;
        std::vector<refuzz::program::xiuos::XiuosProgramCall> calls;
        const char* hyp;
    };
    const std::vector<HeapTeardownProbe> teardown_probes = {
        {"heap_probe_sem_create_delete_zero",
         MakeCalls({{Api::SemCreate,{0u,0u}},{Api::SemDelete,{0u}},{Api::HeapSnapshot,{}}}),
         "sem create+delete heap delta must be 0."},
        {"heap_probe_mutex_create_delete_zero",
         MakeCalls({{Api::MutexCreate,{0u}},{Api::MutexDelete,{0u}},{Api::HeapSnapshot,{}}}),
         "mutex create+delete heap delta must be 0."},
        {"heap_probe_event_create_delete_zero",
         MakeCalls({{Api::EventCreate,{0u,0u}},{Api::EventDelete,{0u}},{Api::HeapSnapshot,{}}}),
         "event create+delete heap delta must be 0."},
        // NOTE: timer create-WITHOUT-start then delete is intentionally NOT
        // a heap probe — it wedges via Class A (softtimer _Delete RmNode on
        // an uninitialized sortlist), so there is no terminal to read a
        // delta from. The running-timer teardown below is the heap probe.
        {"heap_probe_timer_running_delete_zero",
         MakeCalls({{Api::TimerCreate,{0u,0u,0u}},{Api::TimerStartRun,{0u}},{Api::TimerDelete,{0u}},{Api::HeapSnapshot,{}}}),
         "running timer (create+start+delete) heap delta must be 0."},
        {"heap_probe_dq_init_deinit_zero",
         MakeCalls({{Api::DqInit,{0u,2u}},{Api::DqDeinit,{0u}},{Api::HeapSnapshot,{}}}),
         "dataqueue init+deinit heap delta must be 0."},
        {"heap_probe_wq_immediate_zero",
         MakeCalls({{Api::WqCreate,{0u,0u}},{Api::WqSubmit,{0u}},{Api::WqDeinit,{0u}},{Api::HeapSnapshot,{}}}),
         "workqueue create+immediate-submit+deinit heap delta must be 0 "
         "(contrast to the leaking delayed-submit path)."},
        // Config-expanded families: extend the teardown sweep so a create+
        // destroy of each nets 0 (catches teardown leaks in the new modules).
        {"heap_probe_ca_init_release_zero",
         MakeCalls({{Api::CaInit,{0u,2u}},{Api::CaRelease,{0u}},{Api::HeapSnapshot,{}}}),
         "circular_area init(256)+release frees descriptor + data_buffer -> 0."},
        {"heap_probe_gb_create_delete_zero",
         MakeCalls({{Api::GbCreate,{0u,2u,1u}},{Api::GbDelete,{0u}},{Api::HeapSnapshot,{}}}),
         "gatherblock create+delete (no live blocks) frees the pool -> 0."},
        {"heap_probe_avl_insert_delete_all_zero",
         MakeCalls({{Api::AvlInsert,{0u,0u}},{Api::AvlInsert,{0u,1u}},
                    {Api::AvlDelete,{0u,0u}},{Api::AvlDelete,{0u,1u}},
                    {Api::HeapSnapshot,{}}}),
         "AVL insert 2 keys then delete both: a balanced delete path frees every "
         "node -> 0 (the leaking path is the AVL-1 rebalance-drop, separate case)."},
    };
    for (const auto& p : teardown_probes) {
        t.push_back({p.name, p.calls, std::vector<int32_t>{0}, p.hyp});
    }

    // AVL-1 leak accounting: build 4(2(1,3),5), delete leaf 5 (rebalance-drop
    // bug orphans the whole tree), then delete every key. A correct kernel
    // frees all 5 nodes (delta 0); the bug leaves 4 nodes unreachable from the
    // dropped root, so delete-all cannot free them -> positive heap delta. This
    // is the heap-leak witness complementing the AVL_COUNT/SEARCH detectors.
    t.push_back({
        "heap_avl_rebalance_drop_leaks_orphaned_nodes",
        MakeCalls({
            {Api::AvlInsert, {0u, 3u}}, {Api::AvlInsert, {0u, 1u}},
            {Api::AvlInsert, {0u, 4u}}, {Api::AvlInsert, {0u, 0u}},
            {Api::AvlInsert, {0u, 2u}},          // tree 4(2(1,3),5)
            {Api::AvlDelete, {0u, 4u}},          // delete leaf 5 -> AVL-1 drops tree
            {Api::AvlDelete, {0u, 3u}}, {Api::AvlDelete, {0u, 1u}},
            {Api::AvlDelete, {0u, 0u}}, {Api::AvlDelete, {0u, 2u}}, // delete-all (no-ops, root NONE)
            {Api::HeapSnapshot, {}},
        }),
        std::vector<int32_t>{0},
        "FINDING (AVL-1 leak witness): after the rebalance-drop bug sets root to "
        "NONE, the 4 surviving nodes (1,2,3,4) are unreachable, so deleting every "
        "key frees nothing. Expected heap delta 0 (correct kernel frees all on "
        "delete-all); the bug leaks the orphaned nodes -> delta > 0. Confirms "
        "AVL-1 is a heap leak, not only data loss."
    });

    // ── (i) tick.c conversion contract ──────────────────────────────────
    // Oracle-only probes that pin CalculateTickFromTimeMs / CalculateTimeMs-
    // FromTick at TICK_PER_SECOND=100 (virt-rv32). args[0] is the literal
    // scalar, not a slot; aux carries the converter's return. Golden values
    // are computed from the kernel formula:
    //   ticks = (uint32)((uint64)(ms * 100) / 1000), clamp 0 -> MIN_TICKS(1)
    //   ms    = (uint32)((uint64)(ticks * 1000) / 100)
    // Three of these document the contract oddities the gatherblock source
    // audit flagged; they assert the *current* (buggy) behavior, so a future
    // upstream fix flips them and the oracle reports the change.
    struct TickProbe {
        const char* name;
        Api api;
        uint32_t in;
        int32_t out;
        const char* hyp;
    };
    const std::vector<TickProbe> tick_probes = {
        // ms -> ticks. Normal sub-tick and tick-aligned inputs.
        {"tick_ms_to_tick_10ms_is_1tick", Api::TickMsToTick, 10u, 1,
         "10ms == 1 tick at 100Hz: the clean reference conversion."},
        {"tick_ms_to_tick_50ms_is_5ticks", Api::TickMsToTick, 50u, 5,
         "50ms -> 5 ticks (tick-aligned)."},
        {"tick_ms_to_tick_100ms_is_10ticks", Api::TickMsToTick, 100u, 10,
         "100ms -> 10 ticks (tick-aligned)."},
        {"tick_ms_to_tick_1000ms_is_100ticks", Api::TickMsToTick, 1000u, 100,
         "1000ms -> 100 ticks (tick-aligned)."},
        {"tick_ms_to_tick_1ms_floors_to_1tick", Api::TickMsToTick, 1u, 1,
         "1ms (< 1 tick) floors to 0 then clamps to MIN_TICKS=1."},
        // LEAD: ms==0 does not return 0 ticks — the MIN_TICKS clamp makes a
        // "nonblocking" timeout a ~1-tick wait, so AllocBlockMemGather's
        // `if (wait_time == 0) return NONE;` nonblocking branch is dead code.
        {"tick_ms_to_tick_0ms_clamps_to_1tick", Api::TickMsToTick, 0u, 1,
         "LEAD (audit #2): ms==0 yields 1 tick, not 0. A 'nonblocking' alloc "
         "on an exhausted pool actually blocks ~1 tick. The nonblocking guard "
         "is unreachable. Asserts current behavior; flips if upstream fixes it."},
        // LEAD: ms==WAITING_FOREVER(0xFFFFFFFF) overflows the uint32 multiply
        // before the uint64 cast, producing a finite garbage tick count.
        {"tick_ms_to_tick_waiting_forever_overflows", Api::TickMsToTick,
         0xFFFFFFFFu, 4294967,
         "LEAD (audit #1): CalculateTickFromTimeMs(WAITING_FOREVER) returns a "
         "finite 4294967 ticks, NOT infinite. ms*100 overflows mod 2^32 to "
         "0xFFFFFF9C before the (uint64) cast. Callers that special-case "
         "WAITING_FOREVER are safe; gatherblock (which does not) gets a bounded "
         "garbage timeout instead of blocking forever."},
        // ticks -> ms. Round-trips for the clean conversions plus the
        // asymmetry the 0ms clamp introduces.
        {"tick_to_ms_0ticks_is_0ms", Api::TickToMs, 0u, 0,
         "0 ticks -> 0ms (this direction has no MIN clamp)."},
        {"tick_to_ms_1tick_is_10ms", Api::TickToMs, 1u, 10,
         "1 tick -> 10ms: round-trips with the 10ms case. Note the asymmetry "
         "vs ms==0: 0ms->1 tick->10ms, so the converter is NOT involutive at 0."},
        {"tick_to_ms_10ticks_is_100ms", Api::TickToMs, 10u, 100,
         "10 ticks -> 100ms (round-trips the 100ms case)."},
        {"tick_to_ms_100ticks_is_1000ms", Api::TickToMs, 100u, 1000,
         "100 ticks -> 1000ms (round-trips the 1000ms case)."},
    };
    for (const auto& p : tick_probes) {
        t.push_back({p.name, MakeCalls({{p.api, {p.in}}}),
                     std::vector<int32_t>{p.out}, p.hyp});
    }

    // ── (j) circular_area uint8-index truncation ────────────────────────
    // CA_GET_DATA_LENGTH returns CircularAreaGetDataLength in aux. The ring's
    // readidx/writeidx are uint8 but area_length is uint32, so for a ring
    // longer than 256 the `idx = (idx + n) % area_length` assignment truncates
    // mod 256 and the data-length accounting silently diverges from the bytes
    // actually written. length tables: len_idx {0:0,1:64,2:256,3:512};
    // xfer_idx {0:1,1:64,2:300,3:500}. Needs CONFIG_KERNEL_CIRCULAR_AREA
    // (config-expanded). Clean baselines (<=256) assert the contract value and
    // PASS; the >256 cases assert the contract-correct value and FAIL with the
    // truncated value, flagging the bug (same shape as the Class F leak cases:
    // expected = correct, failure = the bug).

    // Clean baseline: 64 bytes into a 256-ring -> data length 64. writeidx=64
    // fits in uint8, no truncation; proves the measurement is sound <=256.
    t.push_back({
        "ca_baseline_write64_into_256_datalen64",
        MakeCalls({
            {Api::CaInit,          {0u, 2u}},      // 256-byte ring
            {Api::CaWrite,         {0u, 1u, 0u}},  // write 64, no force
            {Api::CaGetDataLength, {0u}},
        }),
        std::vector<int32_t>{64},
        "64 bytes into a 256-ring: data length must be 64 (no truncation <=256)."
    });
    // Clean baseline: fill a 64-ring exactly full -> data length 64 (full path).
    t.push_back({
        "ca_baseline_fill_64_full_datalen64",
        MakeCalls({
            {Api::CaInit,          {0u, 1u}},      // 64-byte ring
            {Api::CaWrite,         {0u, 1u, 0u}},  // write 64 -> full
            {Api::CaGetDataLength, {0u}},
        }),
        std::vector<int32_t>{64},
        "Filling a 64-ring exactly: IsFull path returns area_length=64."
    });
    // Clean boundary: a 300-byte write into a 256-ring is capped to 256 and
    // (0+256)%256=0 fits uint8 -> full, data length 256. Shows 256 is the safe
    // boundary: the cap is correct and no truncation occurs at exactly 256.
    t.push_back({
        "ca_baseline_write300cap_into_256_datalen256",
        MakeCalls({
            {Api::CaInit,          {0u, 2u}},      // 256-byte ring
            {Api::CaWrite,         {0u, 2u, 0u}},  // write 300, capped to 256
            {Api::CaGetDataLength, {0u}},
        }),
        std::vector<int32_t>{256},
        "300 capped to 256 into a 256-ring: full, data length 256. 256 is the "
        "safe boundary — (0+256)%256=0 fits uint8, no truncation."
    });
    // Clean baseline: write then read 64 in a 256-ring nets data length 0,
    // proving the read-index accounting is also sound below the boundary.
    t.push_back({
        "ca_baseline_write64_read64_into_256_datalen0",
        MakeCalls({
            {Api::CaInit,          {0u, 2u}},      // 256-byte ring
            {Api::CaWrite,         {0u, 1u, 0u}},  // write 64
            {Api::CaRead,          {0u, 1u}},      // read 64
            {Api::CaGetDataLength, {0u}},
        }),
        std::vector<int32_t>{0},
        "write 64 then read 64 in a 256-ring: data length back to 0."
    });

    // FINDING: 300 bytes into a 512-ring. Contract-correct data length is 300
    // (300 < 512, ring not full). uint8 writeidx = (0+300)%512 = 300 & 0xff =
    // 44, so CircularAreaGetDataLength returns 44. Expect 300 -> FAILS at 44,
    // flagging the truncation bug.
    t.push_back({
        "ca_truncation_write300_into_512_datalen_should_be_300",
        MakeCalls({
            {Api::CaInit,          {0u, 3u}},      // 512-byte ring (>256)
            {Api::CaWrite,         {0u, 2u, 0u}},  // write 300
            {Api::CaGetDataLength, {0u}},
        }),
        std::vector<int32_t>{300},
        "FINDING (config-expanded): 300 bytes into a 512-ring should report "
        "data length 300, but uint8 writeidx truncates (0+300)%512=300 to 44. "
        "readidx/writeidx are uint8 while area_length is uint32 — any ring >256 "
        "silently corrupts its length accounting. Fails here with actual 44."
    });
    // FINDING: 500 bytes into a 512-ring. Contract-correct = 500; uint8
    // writeidx = 500 & 0xff = 244. Expect 500 -> FAILS at 244.
    t.push_back({
        "ca_truncation_write500_into_512_datalen_should_be_500",
        MakeCalls({
            {Api::CaInit,          {0u, 3u}},      // 512-byte ring (>256)
            {Api::CaWrite,         {0u, 3u, 0u}},  // write 500
            {Api::CaGetDataLength, {0u}},
        }),
        std::vector<int32_t>{500},
        "FINDING (config-expanded): 500 bytes into a 512-ring should report "
        "data length 500, but uint8 writeidx truncates 500 to 244. Second "
        "sample of the uint8 index truncation. Fails here with actual 244."
    });

    // ── (k) AVL tree (config-expanded) ──────────────────────────────────
    // data_idx folds to kRefuzzAvlData[16] = {1..16}, so data_idx i -> key
    // i+1. AVL_COUNT returns reachable node count; AVL_CHECK returns an
    // invariant-violation bitmask (0 = ok); AVL_SEARCH returns 1/0. Needs
    // CONFIG_KERNEL_AVL_TREE. Clean baselines assert the contract and PASS;
    // the finding cases assert the contract-correct value and FAIL with the
    // buggy value (same shape as the Class F / circular-area findings).
    t.push_back({
        "avl_baseline_insert3_count3",
        MakeCalls({
            {Api::AvlInsert, {0u, 0u}},  // key 1
            {Api::AvlInsert, {0u, 1u}},  // key 2
            {Api::AvlInsert, {0u, 2u}},  // key 3
            {Api::AvlCount,  {0u}},
        }),
        std::vector<int32_t>{3},
        "Insert 3 distinct keys -> count 3."
    });
    t.push_back({
        "avl_baseline_search_present",
        MakeCalls({{Api::AvlInsert, {0u, 0u}}, {Api::AvlSearch, {0u, 0u}}}),
        std::vector<int32_t>{1},
        "Search for an inserted key -> found (1)."
    });
    t.push_back({
        "avl_baseline_search_absent",
        MakeCalls({{Api::AvlInsert, {0u, 0u}}, {Api::AvlSearch, {0u, 5u}}}),
        std::vector<int32_t>{0},
        "Search for a never-inserted key -> not found (0)."
    });
    t.push_back({
        "avl_baseline_insert7_invariants_hold",
        MakeCalls({
            {Api::AvlInsert, {0u, 0u}}, {Api::AvlInsert, {0u, 1u}},
            {Api::AvlInsert, {0u, 2u}}, {Api::AvlInsert, {0u, 3u}},
            {Api::AvlInsert, {0u, 4u}}, {Api::AvlInsert, {0u, 5u}},
            {Api::AvlInsert, {0u, 6u}}, {Api::AvlCheck,  {0u}},
        }),
        std::vector<int32_t>{0},
        "Insert keys 1..7 (ascending, forces rebalances): AVL_CHECK bitmask 0 "
        "(BST-ordered, balanced, height-cache consistent)."
    });
    t.push_back({
        "avl_baseline_insert1_delete1_count0",
        MakeCalls({
            {Api::AvlInsert, {0u, 0u}},
            {Api::AvlDelete, {0u, 0u}},
            {Api::AvlCount,  {0u}},
        }),
        std::vector<int32_t>{0},
        "Insert then delete the only node -> empty, count 0 (clean leaf delete)."
    });

    // CONTRAST PAIR — same tree 4(2(1,3),5) [insert 4,2,5,1,3], then:
    //  - delete leaf key 1: normal rebalance, count 4 (PASS).
    //  - delete leaf key 5: node 4 reaches BF=+2 with left-child(2) BF==0, so
    //    AvlTreeBalance's four branches all miss, it returns NONE and the whole
    //    tree is dropped -> count 0 (FAIL, expected 4). The finding.
    // (insert sequence repeated inline since MakeCalls takes an init-list.)
    t.push_back({
        "avl_baseline_build5_delete_leaf1_count4",
        MakeCalls({
            {Api::AvlInsert, {0u, 3u}}, {Api::AvlInsert, {0u, 1u}},
            {Api::AvlInsert, {0u, 4u}}, {Api::AvlInsert, {0u, 0u}},
            {Api::AvlInsert, {0u, 2u}},
            {Api::AvlDelete, {0u, 0u}},   // delete key 1 (leaf)
            {Api::AvlCount,  {0u}},
        }),
        std::vector<int32_t>{4},
        "Tree 4(2(1,3),5), delete leaf key 1: normal rebalance keeps 4 nodes."
    });
    t.push_back({
        "avl_build5_delete_leaf5_drops_whole_tree",
        MakeCalls({
            {Api::AvlInsert, {0u, 3u}}, {Api::AvlInsert, {0u, 1u}},
            {Api::AvlInsert, {0u, 4u}}, {Api::AvlInsert, {0u, 0u}},
            {Api::AvlInsert, {0u, 2u}},
            {Api::AvlDelete, {0u, 4u}},   // delete key 5 (leaf)
            {Api::AvlCount,  {0u}},
        }),
        std::vector<int32_t>{4},
        "FINDING (config-expanded): tree 4(2(1,3),5), delete leaf key 5. "
        "Node 4 reaches balance factor +2 while its left child (key 2) has "
        "BF==0; AvlTreeBalance only rebalances for heavy-child BF strictly "
        ">0 or <0, so all four branches miss, new_node stays NONE, and the "
        "whole subtree is returned as NONE. Expected count 4; the bug drops "
        "the entire tree to count 0 (and orphans/leaks nodes 1,2,3,4)."
    });
    // Same drop, witnessed by search instead of count: key 2 should still be
    // present after deleting key 5, but the tree is gone -> not found.
    t.push_back({
        "avl_build5_delete_leaf5_loses_key2",
        MakeCalls({
            {Api::AvlInsert, {0u, 3u}}, {Api::AvlInsert, {0u, 1u}},
            {Api::AvlInsert, {0u, 4u}}, {Api::AvlInsert, {0u, 0u}},
            {Api::AvlInsert, {0u, 2u}},
            {Api::AvlDelete, {0u, 4u}},   // delete key 5
            {Api::AvlSearch, {0u, 1u}},   // search key 2
        }),
        std::vector<int32_t>{1},
        "FINDING witness: after deleting key 5, key 2 should still be found "
        "(1); the subtree-drop bug loses it -> search returns 0."
    });

    // Contract gap: AvlNodeModifyNode(src absent) deletes nothing then inserts
    // dst anyway, so a modify of a non-existent key spuriously ADDS the dst key.
    t.push_back({
        "avl_modify_absent_src_spuriously_inserts_dst",
        MakeCalls({
            {Api::AvlInsert, {0u, 0u}},       // key 1
            {Api::AvlModify, {0u, 8u, 4u}},   // modify key 9 (absent) -> key 5
            {Api::AvlCount,  {0u}},
        }),
        std::vector<int32_t>{1},
        "FINDING (contract gap): modifying a non-existent source key (9) should "
        "be a no-op, but AvlNodeModifyNode deletes (nothing) then inserts the "
        "dst key (5) regardless, growing the tree. Expected count 1; bug gives 2."
    });

    // NOTE: capability (CONFIG_KERNEL_CAPABILITY) oracle cases were removed —
    // the feature is unbootable when enabled (finding CAP-BOOT: KTaskCreate
    // NULL-derefs GetKTaskDescriptor() at early boot), so it cannot be
    // runtime-fuzzed. The wire/dispatch scaffolding is kept dormant behind
    // #ifdef KERNEL_CAPABILITY in the worker; findings CAP-0/BOOT/1/2 are
    // recorded in 01_findings. Restore these oracle cases once the boot break
    // is fixed upstream.

    // ── (m) EVENT_PROCESS options matrix (now wire-exposed) ─────────────
    // EVENT_PROCESS's 4th arg (process_options_idx) is now wire-controllable:
    // idx0=OR|AUTOCLEAN (old default), 1=AND, 2=OR, 3=0(none). aux is the
    // KEventProcess return (EOK=0 on match, -ETIMEOUT=-2 on no match).
    // patterns: idx0=0x1, idx1=0x3 (bits 0+1). These pin the AND/OR matching
    // semantics and confirm the previously-latent SP-2 CHECK(0) spin.
    t.push_back({
        "event_process_or_matches_any_bit",
        MakeCalls({
            {Api::EventCreate,  {0u, 0u}},
            {Api::EventTrigger, {0u, 1u}},        // trigger bits 0x3
            {Api::EventProcess, {0u, 0u, 2u, 2u}},// request 0x1, timeout, OR
        }),
        std::vector<int32_t>{0},
        "EVENT_OR matches if ANY requested bit is set: event has 0x3, request "
        "0x1 -> match -> EOK (0)."
    });
    t.push_back({
        "event_process_and_all_bits_match",
        MakeCalls({
            {Api::EventCreate,  {0u, 0u}},
            {Api::EventTrigger, {0u, 1u}},        // trigger bits 0x3
            {Api::EventProcess, {0u, 1u, 2u, 1u}},// request 0x3, timeout, AND
        }),
        std::vector<int32_t>{0},
        "EVENT_AND matches only if ALL requested bits are set: event 0x3, "
        "request 0x3 -> match -> EOK (0)."
    });
    t.push_back({
        "event_process_and_partial_no_match",
        MakeCalls({
            {Api::EventCreate,  {0u, 0u}},
            {Api::EventTrigger, {0u, 0u}},        // trigger only bit 0x1
            {Api::EventProcess, {0u, 1u, 0u, 1u}},// request 0x3, timeout0, AND
        }),
        std::vector<int32_t>{-2, -10},
        "EVENT_AND with a partially-set mask must NOT match: event 0x1, request "
        "0x3 -> no match -> times out (-ETIMEOUT). Confirms AND requires all bits."
    });
    // FINDING (SP-2, now reachable) — options with neither AND nor OR spins.
    t.push_back({
        "event_process_none_options_spins",
        MakeCalls({
            {Api::EventCreate,  {0u, 0u}},
            {Api::EventProcess, {0u, 0u, 0u, 3u}},// options_idx=3 -> 0 (neither)
        }),
        std::vector<int32_t>{0},
        "FINDING SP-2 (now reachable via wire-exposed options): KEventProcess "
        "with options having neither EVENT_AND nor EVENT_OR hits the "
        "`else { CHECK(0); }` branch (event.c:167) and spins forever. The check "
        "precedes any event-state logic, so no trigger is needed. Expected a "
        "graceful return (aux 0); the kernel wedges -> no terminal."
    });

    // ── (n) KTimerAssignMemberRun (oracle-only) ─────────────────────────
    // assign_ticks_idx -> {100, 0, 0x7FFFFFFF, 0xFFFFFFFF}. AssignMemberRun
    // sets origin_timeslice = ticks (raw, unlike CREATE's uint8 table) then
    // calls _StartRun. aux = the call's return.
    t.push_back({
        "timer_assign_member_run_valid_starts",
        MakeCalls({
            {Api::TimerCreate,          {0u, 0u, 0u}},
            {Api::TimerAssignMemberRun, {0u, 0u}},   // ticks=100 -> starts
        }),
        std::vector<int32_t>{0},
        "Baseline: AssignMemberRun with a valid timeslice (100) sets it and "
        "starts the timer -> EOK."
    });
    t.push_back({
        "timer_assign_member_run_zero_ticks_einvaled",
        MakeCalls({
            {Api::TimerCreate,          {0u, 0u, 0u}},
            {Api::TimerAssignMemberRun, {0u, 0u}},   // ticks=100 -> start first (clean teardown)
            {Api::TimerAssignMemberRun, {0u, 1u}},   // ticks=0
        }),
        std::vector<int32_t>{-10},
        "Contract: AssignMemberRun guards `ticks==0` itself and returns "
        "-EINVALED (-10) gracefully — notably unlike _StartRun, which guards its "
        "timeslice only via a spinning CHECK (see SP-1 below). The timer is "
        "started first (valid AssignMemberRun) so the unstarted-timer Class A "
        "teardown wedge does not mask the -EINVALED return; the ticks==0 call "
        "returns before _StartRun so it neither restarts nor corrupts the timer."
    });
    // FINDING SP-1 (now reachable) — AssignMemberRun lets the caller set
    // origin_timeslice to a raw x_ticks_t; >= TICK_SIZE_MAX/2 trips _StartRun's
    // CHECK and spins. CREATE's uint8 ticks table (max 100) could never reach
    // this; AssignMemberRun's raw ticks arg does.
    t.push_back({
        "timer_assign_member_run_huge_ticks_spins",
        MakeCalls({
            {Api::TimerCreate,          {0u, 0u, 0u}},
            {Api::TimerAssignMemberRun, {0u, 2u}},   // ticks=0x7FFFFFFF
        }),
        std::vector<int32_t>{0},
        "FINDING SP-1 (now reachable via AssignMemberRun's raw ticks): "
        "origin_timeslice=0x7FFFFFFF makes _StartRun's "
        "`CHECK(origin_timeslice < TICK_SIZE_MAX/2)` (softtimer.c:84) fail and "
        "spin forever. Expected a graceful reject (aux 0); the kernel wedges -> "
        "no terminal. The latent timer CHECK-spin from the sweep, now reached."
    });

    // ── (o) priority inversion (multi-task scheduler scenario) ──────────
    // New harness capability: TASK_GET_PRIO observes a task's cur_prio
    // (slot>=XIUOS_TASK_SLOTS = the worker itself), TASK_SPAWN_BLOCK_MUTEX_HIGH
    // spawns a victim ABOVE the worker that blocks on a worker-held mutex.
    // XiUOS direction: HIGHER numeric = HIGHER priority (KTASK_LOWEST_PRIORITY=0).
    // Worker=5, the contending victim=7 (REFUZZ_VICTIM_PRIORITY_ABOVE).
    t.push_back({
        "task_get_prio_self_baseline",
        MakeCalls({{Api::TaskGetPrio, {0xFFu}}}),
        std::vector<int32_t>{5},
        "Baseline: TASK_GET_PRIO(self) reads the worker's cur_prio = "
        "REFUZZ_WORKER_PRIORITY (5). Confirms the scheduler observable works."
    });
    // FINDING (scheduler/QoS, not memory-safety): the worker holds a mutex, then
    // a HIGHER-priority (7) victim blocks on it. A priority-inheriting mutex
    // would boost the holder (worker) up to 7 so it can release promptly and the
    // high task isn't starved by a medium one. XiUOS's PI boost is commented out
    // (mutex.c:114-120, "dont use KTaskPrioSet, for it's bugged"), so the holder
    // stays at 5 -> priority inversion is unmitigated. PI is a present-but-
    // disabled design goal (the commented code), so this is reportable as a
    // realtime-semantics defect, not a crash.
    t.push_back({
        "mutex_priority_inversion_holder_not_boosted",
        MakeCalls({
            {Api::MutexCreate,             {0u}},
            {Api::MutexObtain,             {0u, 0u}},   // worker becomes holder (prio 5)
            {Api::TaskSpawnBlockMutexHigh, {0u, 0u}},   // prio-7 victim blocks on mutex0
            {Api::TaskGetPrio,             {0xFFu}},     // worker (holder) cur_prio
        }),
        std::vector<int32_t>{7},
        "FINDING (priority inversion, QoS): a priority-inheriting mutex would "
        "boost the holder (worker) to the blocked higher-priority victim's "
        "priority (7). XiUOS leaves the boost commented out, so the holder stays "
        "at 5 (aux=5, expected 7 = FAIL). Root cause: KTaskPrioSet doesn't "
        "reschedule, which is why PI was disabled by the kernel authors."
    });

    // ── (p) heap structural integrity (detector upgrade for silent corruption)
    // HEAP_INTEGRITY walks the buddy heap by boundary tags and returns the
    // first violated invariant in aux (0 = consistent). A correct allocator
    // keeps it 0, so expected_aux={0}; a nonzero aux is the FINDING. This turns
    // "state corrupted but not yet faulted" into a reported bug (the gap that
    // makes long fuzz campaigns miss silent corruption).
    t.push_back({
        "heap_integrity_clean_baseline",
        MakeCalls({{Api::HeapIntegrity, {}}}),
        std::vector<int32_t>{0},
        "Baseline: a freshly-booted heap is structurally consistent, so "
        "HEAP_INTEGRITY returns 0. Guards against the checker false-positiving "
        "on normal kernel allocations (if this FAILs, the invariant is too "
        "strict, not a kernel bug)."
    });
    // FINDING (Class B, silent — proven without a fault): slot0 gets a 4B
    // msg_buf -> 16B buddy block (< SIZEOF_XSFREENODE_MEM=20); slot1 is a live
    // neighbor. Deleting slot0 frees the 16B block, and AddNewNodeIntoBuddy's
    // freelist `prev` write (offset 16) overflows into slot1's
    // DynamicAllocNode.size (root cause: BigMemMalloc missing a min-block-size,
    // byte_manage.c:347). The worker's per-call CheckDynamicMemoryIntegrity
    // catches the now-corrupt boundary tag (invariant 3/4) right after the
    // delete — before slot1 is freed at teardown and traps — and aborts with
    // STATE_VIOLATION (aux = invariant code). The old hang-only detector saw
    // nothing until that later teardown free faulted.
    t.push_back({
        "heap_integrity_class_b_silent_overwrite",
        MakeCalls({
            {Api::MsgqCreate, {0u, 0u, 0u}},   // slot0: 4B msg_buf -> 16B block
            {Api::MsgqCreate, {1u, 0u, 0u}},   // slot1: live neighbor
            {Api::MsgqDelete, {0u}},           // free slot0 -> clobbers slot1 header (silent)
        }),
        std::vector<int32_t>{0},
        "FINDING (Class B heap corruption, silent): a correct allocator keeps "
        "the heap consistent (expected aux=0); the undersized-block overwrite "
        "leaves a nonzero boundary-tag violation that the per-call check reports "
        "with NO trap. Exactly the silent state corruption the hang-only "
        "campaign detector misses. Fix: byte_manage.c:347 min-block-size."
    });

    return t;
}

}  // namespace

XiuosFuzzSession::OracleSummary XiuosFuzzSession::RunOracleSelfTest() {
    OracleSummary r;
    if (!booted_ || !chan_) return r;

    const auto cases = BuildOracleCaseTable();
    const auto out_dir = cfg_.vm_workdir / "oracle";
    std::error_code ec;
    std::filesystem::create_directories(out_dir, ec);

    for (const auto& c : cases) {
        // Encode the call sequence to wire payload (same format Bootstrap /
        // Step use). Use the program/ free-function encoder.
        const auto payload = refuzz::program::xiuos::XiuosEncodeProgram(
            std::span<const refuzz::program::xiuos::XiuosProgramCall>(
                c.calls.data(), c.calls.size()),
            refuzz::program::xiuos::XiuosSuiteId::CommonKernel);

        cc::ChannelDispatchRequest req;
        req.executor_id      = ++next_executor_id_;
        req.seed_id          = 0;
        req.origin_seed_id   = 0;
        req.payload          = payload;
        req.timeout_ms       = cfg_.exec_timeout_ms;
        req.target_worker_id = 0;

        auto submit = chan_->Submit(req, std::chrono::microseconds(0));
        std::size_t retries = 0;
        while (submit.status == cc::ChannelSubmitStatus::kBusy && retries < 200) {
            DrainEventsAndFeedback(std::chrono::milliseconds(20));
            submit = chan_->Submit(req, std::chrono::microseconds(0));
            ++retries;
        }
        if (submit.status != cc::ChannelSubmitStatus::kAccepted) continue;

        ++r.cases_run;
        ++stats_.oracle_cases_run;

        // Drain for terminal event matching our executor.
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(8);
        bool saw = false;
        int32_t actual_aux = 0;
        std::string actual_status = "?";
        while (!saw && std::chrono::steady_clock::now() < deadline) {
            channel::EventList events;
            chan_->DrainEvents(events, std::chrono::milliseconds(100));
            for (const auto& ev : events) {
                if (ev.IsCompletion() && ev.AsCompletion() &&
                    ev.AsCompletion()->ctx.executor_id == req.executor_id) {
                    actual_aux = ev.AsCompletion()->vendor_aux;
                    actual_status = "ok";
                    saw = true;
                } else if (ev.IsAbnormal() && ev.AsAbnormal() &&
                           ev.AsAbnormal()->ctx.executor_id == req.executor_id) {
                    actual_status = "abnormal";
                    saw = true;
                }
                { const auto _out = fb_engine_.Process(ev); AdmitFromVerdict(ev, _out); }
            }
            DrainTickToFixpoint();
        }

        bool aux_match = false;
        for (int32_t e : c.expected_aux) {
            if (actual_aux == e) { aux_match = true; break; }
        }
        const bool pass = saw && (actual_status == "ok") && aux_match;
        // XIUOS_ORACLE_VERBOSE=1 logs every case's actual aux, not just the
        // failures that land in oracle/*.json. Lets a contract-pin case (e.g.
        // the tick.c probes, whose "pass" IS the evidence the worker returned
        // the golden value) leave a positive trace in the run log.
        if (const char* v = std::getenv("XIUOS_ORACLE_VERBOSE"); v && *v == '1') {
            std::fprintf(stderr, "ORACLE_CASE %-52s %s aux=%d (expected",
                         c.name, pass ? "PASS" : "FAIL", actual_aux);
            for (int32_t e : c.expected_aux) std::fprintf(stderr, " %d", e);
            std::fprintf(stderr, ")\n");
        }
        if (!pass) {
            ++r.failures;
            ++stats_.oracle_failures;
            std::ofstream f(out_dir / (std::string(c.name) + ".json"));
            if (f) {
                f << "{\n"
                  << "  \"case\": \"" << c.name << "\",\n"
                  << "  \"status\": \"" << actual_status << "\",\n"
                  << "  \"expected_aux\": [";
                for (std::size_t i = 0; i < c.expected_aux.size(); ++i) {
                    if (i) f << ", ";
                    f << c.expected_aux[i];
                }
                f << "],\n"
                  << "  \"actual_aux\": " << actual_aux << ",\n"
                  << "  \"saw_terminal\": " << (saw ? "true" : "false") << ",\n"
                  << "  \"hypothesis\": \"" << c.hypothesis << "\"\n"
                  << "}\n";
            }
        }

        // Isolate every case on a fresh worker. Cases that spawn a victim
        // into a blocking primitive (WqueueWait / TASK_SPAWN_BLOCK_*) and
        // then delete it leave kernel-side residue — e.g. a dangling node
        // in xiaoshan_delay_head (Class F) from WqueueWait's internal
        // KTaskSetDelay. Without isolation that residue wedges a LATER
        // case, conflating cases. We deliberately do NOT scrub the residue
        // worker-side (that would mask the real kernel bug); instead each
        // case starts from a clean QEMU. Cheap enough: the oracle is a
        // periodic regression check, not a hot loop. The final case's
        // recovery is harmless.
        if (!RecoverFromWedge()) {
            // Could not rebuild a worker; remaining cases can't run.
            break;
        }
    }
    return r;
}

void XiuosFuzzSession::DrainTail(std::chrono::milliseconds budget) {
    DrainEventsAndFeedback(budget);
}

// ──────────────────────── Accessors ─────────────────────────────────────

XiuosFuzzSession::Stats XiuosFuzzSession::Snapshot() const {
    Stats s = stats_;
    s.corpus_current        = store_.Size();
    s.bucket_count          = bucket_.BucketCount();
    s.bucket_seeds          = bucket_.TotalRecordedSeeds();
    s.unique_seed_ids_picked = seen_seed_ids_.size();
    return s;
}

fuzzer::XiuosMutatorEngine::Stats XiuosFuzzSession::MutatorStats() const {
    return mutator_.GetStats();
}

std::size_t XiuosFuzzSession::CorpusSize()  const { return store_.Size(); }
std::size_t XiuosFuzzSession::BucketCount() const { return bucket_.BucketCount(); }
std::size_t XiuosFuzzSession::BucketSeeds() const { return bucket_.TotalRecordedSeeds(); }

}  // namespace refuzz::control::xiuos
