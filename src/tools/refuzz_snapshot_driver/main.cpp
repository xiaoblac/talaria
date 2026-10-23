// refuzz_snapshot_driver — standalone witness tool for the snapshot CHANNEL BACKEND.
//
// Production snapshot fuzzing is the `qemu_ivshmem_snapshot_linux` backend driven
// by the orchestrator (refuzz <snapshot config>). This tool assembles the SAME
// components by hand — ShmInfra + Runtime(snapshot_fuzzing) + IvshmemControlPlane +
// the production `SnapshotDataPlane` (wraps IvshmemDataPlane + QMP savevm/loadvm) —
// boots them, and drives Submit/Poll directly to run determinism / state-isolation
// witnesses without the full FuzzerLoop. It exercises the REAL backend component,
// so what it validates is what production runs. (Decoupled from the deleted
// control/snapshot session per the modular redo.)
//
// Usage: refuzz_snapshot_driver [trace_dir | corpus_dir | program_file]
//   trace dir (exec_trace_*.bin) → up to 12 distinct wire programs
//   corpus dir (<hex>/payload.bin) → syz text → wire (mount-family first)
//   program file → syz text (else raw wire bytes); no arg → 1-byte placeholder
// Each program runs 3× from S0; identical canonical PC-set + per-call result across
// restores = deterministic (state isolation held).

#include "refuzz/channel/control/ivshmem_control_plane.hpp"
#include "refuzz/channel/control/session_timing.hpp"
#include "refuzz/channel/data/data_plane.hpp"
#include "refuzz/channel/data/ivshmem_data_plane.hpp"
#include "refuzz/channel/data/snapshot_data_plane.hpp"
#include "refuzz/channel/infra/shm_infra.hpp"
#include "refuzz/channel/runtime/deploy_bundle.hpp"
#include "refuzz/channel/runtime/runtime.hpp"
#include "refuzz/channel/runtime/runtime_config.hpp"
#include "refuzz/channel/substrate/substrate.hpp"

#include "refuzz/feedback/coverage_semantics.hpp"
#include "refuzz/feedback/decode/syz_exec_result_decode.hpp"
#include "refuzz/feedback/feedback_codec.hpp"
#include "refuzz/proto_domain/types.hpp"
#include "worker/backend/syz_exec_runner.hpp"

#include "refuzz/program/syz/encoding.hpp"
#include "refuzz/program/syz/exec_wire.hpp"
#include "refuzz/program/syz/exec_wire_decode.hpp"
#include "refuzz/program/syz/target.hpp"
#include "trace_reader.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

using namespace std::chrono;
namespace rcr = refuzz::channel::runtime;
namespace rci = refuzz::channel::infra;
namespace rcc = refuzz::channel::control;
namespace rcd = refuzz::channel::data;

namespace {

struct Program {
    std::vector<uint8_t>     payload;
    std::size_t              num_calls = 0;
    std::vector<std::string> call_names;
    bool                     has_mount = false;
};

Program DecodeProgram(std::vector<uint8_t> bytes)
{
    namespace psyz = refuzz::program::syz;
    Program p;
    p.payload = std::move(bytes);
    auto wp = psyz::decode_exec_wire(
        std::span<const uint8_t>(p.payload.data(), p.payload.size()));
    if (!wp) return p;
    p.num_calls = static_cast<std::size_t>(wp->num_calls);
    const auto& sc = psyz::Target::linux_amd64().syscalls();
    for (const auto& instr : wp->instrs) {
        if (const auto* c = std::get_if<psyz::WireCall>(&instr)) {
            std::string nm = (c->call_id < sc.size()) ? sc[c->call_id]->name() : "?";
            if (nm.find("mount") != std::string::npos) p.has_mount = true;
            p.call_names.push_back(std::move(nm));
        }
    }
    return p;
}

std::optional<std::vector<uint8_t>> TextProgToWire(std::string_view text)
{
    namespace psyz = refuzz::program::syz;
    psyz::TextDecoder dec(psyz::Target::linux_amd64(), psyz::DecodeMode::kNonStrict);
    auto prog = dec.decode(text);
    if (!prog) return std::nullopt;
    auto bytes = psyz::serialize_for_exec(**prog);
    if (!bytes) return std::nullopt;
    return std::move(*bytes);
}

const char* KindName(rcd::DispatchOutcomeKind k)
{
    switch (k) {
        case rcd::DispatchOutcomeKind::kOk:             return "kOk";
        case rcd::DispatchOutcomeKind::kPartial:        return "kPartial";
        case rcd::DispatchOutcomeKind::kNoResult:       return "kNoResult";
        case rcd::DispatchOutcomeKind::kTimeout:        return "kTimeout";
        case rcd::DispatchOutcomeKind::kCancelled:      return "kCancelled";
        case rcd::DispatchOutcomeKind::kWorkerSignaled: return "kWorkerSignaled";
        case rcd::DispatchOutcomeKind::kChildAborted:   return "kChildAborted";
        case rcd::DispatchOutcomeKind::kHarnessFatal:   return "kHarnessFatal";
        case rcd::DispatchOutcomeKind::kHarnessRecovered:return "kHarnessRecovered";
        case rcd::DispatchOutcomeKind::kInfraFault:     return "kInfraFault";
        case rcd::DispatchOutcomeKind::kUnknown:        return "kUnknown";
    }
    return "?";
}

std::vector<Program> CollectPrograms(int argc, char** argv)
{
    namespace fs = std::filesystem;
    constexpr std::size_t kMaxPrograms = 12;
    std::vector<Program> programs;
    if (argc >= 2 && fs::is_directory(argv[1])) {
        namespace rep = refuzz::oracle::replayer;
        auto sessions = rep::CollectAndSortTraces(argv[1]);
        if (!sessions.empty()) {  // trace dir
            std::vector<uint64_t> seen;
            rep::TraceCallbacks cbs;
            cbs.on_exec_request = [&](const rep::ExecRequestEvent& ev) {
                if (programs.size() >= kMaxPrograms || ev.payload.empty()) return;
                uint64_t hv = 1469598103934665603ULL;
                for (uint8_t b : ev.payload) { hv ^= b; hv *= 1099511628211ULL; }
                for (uint64_t s : seen) if (s == hv) return;
                Program p = DecodeProgram(ev.payload);
                if (p.num_calls == 0) return;
                seen.push_back(hv);
                programs.push_back(std::move(p));
            };
            rep::ReplayOneFile(sessions.front(), cbs);
            std::fprintf(stderr, "[snap-driver] %zu programs from trace %s\n",
                         programs.size(), sessions.front().file_path.c_str());
        } else {  // corpus text dir — mount-family floated to front
            std::vector<fs::path> files;
            for (auto& e : fs::recursive_directory_iterator(argv[1]))
                if (e.is_regular_file() && e.path().filename() == "payload.bin")
                    files.push_back(e.path());
            std::sort(files.begin(), files.end());
            std::vector<Program> all;
            for (auto& fp : files) {
                std::ifstream f(fp);
                std::string text((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>{});
                auto wire = TextProgToWire(text);
                if (!wire) continue;
                Program p = DecodeProgram(std::move(*wire));
                if (p.num_calls != 0) all.push_back(std::move(p));
            }
            std::stable_sort(all.begin(), all.end(),
                [](const Program& a, const Program& b) { return a.has_mount && !b.has_mount; });
            for (auto& p : all) {
                if (programs.size() >= kMaxPrograms) break;
                programs.push_back(std::move(p));
            }
            std::fprintf(stderr, "[snap-driver] %zu programs from corpus %s (%zu total)\n",
                         programs.size(), argv[1], files.size());
        }
    } else if (argc >= 2) {
        std::ifstream f(argv[1], std::ios::binary);
        if (f) {
            std::vector<uint8_t> raw(std::istreambuf_iterator<char>(f),
                                     std::istreambuf_iterator<char>{});
            auto wire = TextProgToWire(std::string_view(
                reinterpret_cast<const char*>(raw.data()), raw.size()));
            programs.push_back(wire ? DecodeProgram(std::move(*wire))
                                    : DecodeProgram(std::move(raw)));
        }
    } else {
        Program p; p.payload = {0x00};
        programs.push_back(std::move(p));
        std::fprintf(stderr, "[snap-driver] no payload; 1-byte placeholder (plumbing only)\n");
    }
    return programs;
}

// Decode one completion → unique normalized PC count + canonical PC-set hash +
// per-call signature. Mirrors corpus_replay.cpp:145-189.
struct Decoded { long total_pcs = -1; uint64_t cov_hash = 0; std::string sig; };
Decoded DecodeOutcome(const rcd::DispatchOutcome& e, std::size_t nc,
                      refuzz::fuzzer::CoverageFeedbackCodec& codec)
{
    Decoded d;
    if (nc == 0 || e.output.empty()) return d;
    std::vector<uint8_t> out = e.output;
    refuzz::proto::FeedbackDelta delta;
    if (codec.Extract(&out, &delta) == refuzz::fuzzer::ParseFeedbackStatus::kMalformed) return d;
    const std::size_t head = nc * sizeof(refuzz::worker::SyzExecResult);
    const std::size_t exp_tail =
        (out.size() >= head) ? (out.size() - head) / sizeof(std::uint64_t) : 0;
    auto dec = refuzz::feedback::decode::DecodeSyzExecResultsWithCoverage(
        std::span<const std::uint8_t>(out.data(), out.size()), nc, exp_tail);
    if (dec.results.size() != nc) return d;
    std::vector<std::uint64_t> pcs;
    char sb[96];
    for (std::size_t i = 0; i < nc; ++i) {
        const auto& r = dec.results[i];
        const std::size_t end = static_cast<std::size_t>(r.cover_offset) +
                                static_cast<std::size_t>(r.cover_count);
        std::vector<std::uint64_t> slice;
        if (r.cover_count > 0 && end <= dec.coverage_tail.size())
            slice.assign(dec.coverage_tail.begin() + r.cover_offset,
                         dec.coverage_tail.begin() + end);
        auto norm = refuzz::fuzzer::NormalizeCoverageEntries(std::move(slice), codec.config());
        pcs.insert(pcs.end(), norm.begin(), norm.end());
        std::snprintf(sb, sizeof(sb), "c%zu{ret=%lld,err=%d,fl=0x%x,cov=%zu} ",
                      i, static_cast<long long>(r.ret), r.err, r.flags, norm.size());
        d.sig += sb;
    }
    std::sort(pcs.begin(), pcs.end());
    pcs.erase(std::unique(pcs.begin(), pcs.end()), pcs.end());
    d.total_pcs = static_cast<long>(pcs.size());
    uint64_t h = 1469598103934665603ULL;
    for (uint64_t pc : pcs)
        for (int s = 0; s < 64; s += 8) { h ^= (pc >> s) & 0xff; h *= 1099511628211ULL; }
    d.cov_hash = h;
    return d;
}

}  // namespace

int main(int argc, char** argv)
{
    std::vector<Program> programs = CollectPrograms(argc, argv);
    if (programs.empty()) {
        std::fprintf(stderr, "[snap-driver] no decodable programs\n");
        return 2;
    }
    for (std::size_t i = 0; i < programs.size(); ++i) {
        std::string calls;
        for (const auto& c : programs[i].call_names) { calls += c; calls += ' '; }
        std::fprintf(stderr, "[snap-driver] program[%zu] num_calls=%zu calls=[%s]%s\n",
                     i, programs[i].num_calls, calls.c_str(),
                     programs[i].has_mount ? "  <<MOUNT WITNESS>>" : "");
    }

    const std::string workdir  = "/workspace/talaria/run/snapshot_mode";
    const std::string shm_path = workdir + "/ivshmem.shm";
    std::error_code ec; std::filesystem::create_directories(workdir, ec);

    // ── assemble the snapshot backend's components by hand ───────────────
    rci::InfraConfig infra_cfg;
    infra_cfg.shm_path  = shm_path;
    infra_cfg.n_workers = 1;
    auto shm = std::make_shared<rci::ShmInfra>(infra_cfg);
    if (auto r = shm->Init(); !r.ok()) {
        std::fprintf(stderr, "[snap-driver] ShmInfra.Init: %s\n", r.error().message.c_str());
        return 1;
    }
    auto backbone = shm->Backbone();

    rcr::RuntimeConfig rcfg;
    rcfg.pool.pool_size = 1;
    auto& inst = rcfg.instance;
    inst.arch            = "amd64";
    inst.kernel          = "/workspace/syzkaller/kernel/build-kasan/arch/x86/boot/bzImage";
    inst.disk_image      = "/workspace/images-test-linux5.14/bookworm.img";
    inst.ssh_key         = "/workspace/images-test-linux5.14/bookworm.id_rsa";
    inst.ssh_user        = "root";
    inst.workdir         = workdir;
    inst.mem_mb          = 2048;
    inst.cpu             = 1;
    inst.snapshot_fuzzing = true;
    inst.qmp_enable       = true;
    inst.ivshmem_bytes    = shm->total_size();
    inst.ivshmem_mode     = "plain";
    inst.ivshmem_path     = shm_path;
    inst.serial_log_path  = workdir + "/serial.log";

    refuzz::channel::worker::WorkerConfig wcfg;
    wcfg.n_workers = 1;
    wcfg.worker_binary_host_path =
        "/workspace/talaria/build-llvm20/executor/channel/worker/ivshmem_worker";
    wcfg.worker_remote_path = "/tmp/ivshmem_worker";

    auto rt_res = rcr::Runtime::Create(rcfg, rcr::MakeVmSubstratePoolOps(rcfg.instance), wcfg);
    if (!rt_res.ok()) {
        std::fprintf(stderr, "[snap-driver] Runtime::Create: %s\n", rt_res.error().message.c_str());
        return 1;
    }
    rcr::Runtime* runtime_raw = rt_res.value().get();
    auto runtime = std::move(rt_res.value());

    rcc::SessionTiming timing;
    rcc::IvshmemControlPlane cp(backbone, shm.get(), timing);

    rcd::IvshmemDataPlaneOptions dopt;
    dopt.shm_path     = shm_path;
    dopt.use_doorbell = false;
    auto inner = std::make_unique<rcd::IvshmemDataPlane>(
        backbone, shm.get(), cp.GetSendabilityView(), cp.GetRegistrationHook(), std::move(dopt));
    rcd::SnapshotDataPlane sdp(
        std::move(inner), [runtime_raw] { return runtime_raw->MonitorEndpoint(0); }, "S0");

    // ── manual boot (no Channel/Health/loop_thread) ─────────────────────
    auto fail = [&](const char* what, const refuzz::channel::Result<void>& r) -> int {
        std::fprintf(stderr, "[snap-driver] %s: %s\n", what, r.error().message.c_str());
        runtime->StopVM(0);
        return 1;
    };
    if (auto r = sdp.StartServer();        !r.ok()) return fail("StartServer", r);
    if (auto r = runtime->StartVM(0);      !r.ok()) return fail("StartVM", r);
    rcr::DeployBundle bundle;
    bundle.artifacts.push_back(rcr::DeployArtifact{
        wcfg.worker_binary_host_path, wcfg.worker_remote_path, 0755});
    bundle.worker_start_cmd = wcfg.worker_remote_path + " --worker-id {worker_id}";
    if (auto r = runtime->DeployArtifacts(0, bundle); !r.ok()) return fail("DeployArtifacts", r);
    if (auto r = sdp.Prepare();            !r.ok()) return fail("Prepare", r);
    if (auto r = cp.BeginSession();        !r.ok()) return fail("BeginSession", r);
    if (auto r = runtime->StartAllWorkers(0); !r.ok()) return fail("StartAllWorkers", r);
    if (auto r = cp.WaitAllWorkersReady(milliseconds(15'000)); !r.ok())
        return fail("WaitAllWorkersReady", r);
    std::fprintf(stderr, "[snap-driver] worker ready; driving SnapshotDataPlane "
                         "(savevm S0 lazily on first Submit)\n");

    // ── per-program × per-restore witness via the production SnapshotDataPlane ─
    refuzz::fuzzer::CoverageFeedbackCodec codec{};
    const int kRestores = 3;
    uint64_t exec_id = 0;
    int det_programs = 0, mount_witnesses = 0, mount_isolated = 0;
    int crashes = 0, hangs = 0;
    for (std::size_t pi = 0; pi < programs.size(); ++pi) {
        const Program& prog = programs[pi];
        if (prog.has_mount) ++mount_witnesses;
        std::fprintf(stderr, "\n[snap-driver] program[%zu] num_calls=%zu%s\n",
                     pi, prog.num_calls, prog.has_mount ? "  <<MOUNT WITNESS>>" : "");
        uint64_t first_cov = 0; std::string first_sig; bool have_first = false, det = true;
        int completions = 0;
        for (int r = 0; r < kRestores; ++r) {
            rcd::IDataPlane::SubmitInput in;
            in.worker_id    = 0;
            in.executor_id  = ++exec_id;
            in.dispatch_gen = 1;
            in.payload_data = prog.payload.data();
            in.payload_size = prog.payload.size();
            in.exec_flags   = 0;  // INTRA_SERIAL | SHAPE_SINGLE
            const rcd::SubmitOutcome oc = sdp.Submit(in);  // savevm/loadvm cycle inside
            if (oc != rcd::SubmitOutcome::kSent) {
                std::fprintf(stderr, "[snap-driver]   run%d: Submit=%d (not kSent)\n",
                             r, static_cast<int>(oc));
                det = false; continue;
            }
            auto l0 = steady_clock::now();
            std::vector<rcd::DispatchOutcome> events;
            for (int t = 0; t < 60 && events.empty(); ++t) sdp.Poll(events, milliseconds(100));
            const long long ms = duration_cast<milliseconds>(steady_clock::now() - l0).count();
            if (events.empty()) {
                std::fprintf(stderr, "[snap-driver]   run%d: NO completion after %lld ms\n", r, ms);
                det = false; continue;
            }
            const auto& e = events.front();
            ++completions;
            const bool is_crash = (e.kind == rcd::DispatchOutcomeKind::kWorkerSignaled ||
                                   e.kind == rcd::DispatchOutcomeKind::kChildAborted ||
                                   e.crash_signal > 0);
            const bool is_hang = (e.kind == rcd::DispatchOutcomeKind::kTimeout);
            if (is_crash) ++crashes;
            if (is_hang)  ++hangs;
            const Decoded d = DecodeOutcome(e, prog.num_calls, codec);
            if (!have_first) { first_cov = d.cov_hash; first_sig = d.sig; have_first = true; }
            else if (d.cov_hash != first_cov || d.sig != first_sig) det = false;
            std::fprintf(stderr,
                         "[snap-driver]   run%d: %lld ms kind=%s out=%zuB covset=%016llx pcs=%ld%s%s | %s\n",
                         r, ms, KindName(e.kind), e.output.size(),
                         static_cast<unsigned long long>(d.cov_hash), d.total_pcs,
                         is_crash ? " CRASH" : "", is_hang ? " HANG" : "", d.sig.c_str());
        }
        const bool det_ok = det && completions == kRestores;
        std::fprintf(stderr, "[snap-driver] program[%zu] -> %s (%d/%d)\n",
                     pi, det_ok ? "DETERMINISTIC" : "NON-DETERMINISTIC", completions, kRestores);
        if (det_ok) ++det_programs;
        if (prog.has_mount && det_ok) {
            ++mount_isolated;
            std::fprintf(stderr, "[snap-driver] program[%zu] STATE-ISOLATION HELD\n", pi);
        }
    }

    runtime->StopAllWorkers(0);
    sdp.Close();
    runtime->StopVM(0);
    std::fprintf(stderr,
                 "\n[snap-driver] SUMMARY: programs=%zu det=%d/%zu crashes=%d hangs=%d "
                 "mount_witnesses=%d (isolation held %d)\n",
                 programs.size(), det_programs, programs.size(), crashes, hangs,
                 mount_witnesses, mount_isolated);
    return 0;
}
