// SnapshotDataPlane impl — see header + docs/plans/snapshot-session-integration.md.

#include "refuzz/channel/data/snapshot_data_plane.hpp"

#include "refuzz/logging/host_logger.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace refuzz::channel::data {

// Minimal QMP/HMP client over the monitor TCP endpoint ("host:port").
struct SnapshotDataPlane::Qmp {
    int fd = -1;
    std::string acc;

    bool Connect(const std::string& hostport)
    {
        const auto colon = hostport.find(':');
        if (colon == std::string::npos) return false;
        const std::string host = hostport.substr(0, colon);
        const int port = ::atoi(hostport.c_str() + colon + 1);
        fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return false;
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(static_cast<uint16_t>(port));
        ::inet_pton(AF_INET, host.c_str(), &sa.sin_addr);
        return ::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0;
    }
    bool Pump()
    {
        char b[8192];
        ssize_t n = ::recv(fd, b, sizeof(b), 0);
        if (n > 0) acc.append(b, static_cast<size_t>(n));
        return n > 0;
    }
    std::string WaitReturn()
    {
        for (int guard = 0; guard < 2'000'000; ++guard) {
            size_t nl;
            while ((nl = acc.find('\n')) != std::string::npos) {
                std::string line = acc.substr(0, nl);
                acc.erase(0, nl + 1);
                if (line.find("\"return\"") != std::string::npos ||
                    line.find("\"error\"") != std::string::npos)
                    return line;
            }
            if (!Pump()) return "";
        }
        return "";
    }
    std::string Cmd(const std::string& c)
    {
        std::string l = c + "\n";
        ::send(fd, l.data(), l.size(), 0);
        return WaitReturn();
    }
    std::string Hmp(const std::string& cl)
    {
        return Cmd("{\"execute\":\"human-monitor-command\","
                   "\"arguments\":{\"command-line\":\"" + cl + "\"}}");
    }
    ~Qmp()
    {
        if (fd >= 0) ::close(fd);
    }
};

SnapshotDataPlane::SnapshotDataPlane(std::unique_ptr<IDataPlane> inner,
                                     std::function<std::string()> monitor_endpoint_fn,
                                     std::string snapshot_tag,
                                     std::string vmlinux_path,
                                     uint32_t wedge_threshold_ms)
    : inner_(std::move(inner)),
      monitor_endpoint_fn_(std::move(monitor_endpoint_fn)),
      tag_(std::move(snapshot_tag)),
      vmlinux_path_(std::move(vmlinux_path)),
      wedge_threshold_ms_(wedge_threshold_ms)
{
}

SnapshotDataPlane::~SnapshotDataPlane() = default;

Result<void> SnapshotDataPlane::StartServer() { return inner_->StartServer(); }

Result<void> SnapshotDataPlane::Prepare()
{
    auto r = inner_->Prepare();
    if (!r.ok()) return r;
    // VM is up by Prepare (Boot order: StartVM → ... → dp.Prepare); connect QMP now.
    EnsureQmpConnected();
    return Result<void>::Ok();
}

void SnapshotDataPlane::Close()
{
    inner_->Close();
    qmp_.reset();
}

void SnapshotDataPlane::Pause()  { inner_->Pause(); }
void SnapshotDataPlane::Resume() { inner_->Resume(); }

bool SnapshotDataPlane::EnsureQmpConnected()
{
    if (qmp_ && qmp_->fd >= 0) return true;
    if (!monitor_endpoint_fn_) return false;
    const std::string ep = monitor_endpoint_fn_();
    if (ep.empty()) return false;
    qmp_ = std::make_unique<Qmp>();
    if (!qmp_->Connect(ep)) {
        refuzz::logging::HostLineBuilder("snapshot_dp", "qmp_connect_failed")
            << "endpoint=" << ep << "\n";
        qmp_.reset();
        return false;
    }
    qmp_->Cmd("{\"execute\":\"qmp_capabilities\"}");
    return true;
}

bool SnapshotDataPlane::EnsureSnapshotSaved()
{
    if (s0_saved_) return true;
    if (!EnsureQmpConnected()) return false;
    // Exclude the ivshmem-plain RAMBlock from the snapshot so host writes to the
    // task slot/input survive loadvm.
    qmp_->Hmp("migrate_set_capability x-ignore-shared on");
    // Capture the worker PARKED in WaitTask (first Submit, before any loadvm).
    qmp_->Hmp("stop");
    qmp_->Hmp("savevm " + tag_);
    const std::string snaps = qmp_->Hmp("info snapshots");
    if (snaps.find(tag_) == std::string::npos) {
        refuzz::logging::HostLineBuilder("snapshot_dp", "savevm_failed")
            << "no snapshot '" << tag_ << "' (disk not a writable qcow2?)\n";
        qmp_->Hmp("cont");
        return false;
    }
    s0_saved_ = true;
    return true;
}

SubmitOutcome SnapshotDataPlane::Submit(const SubmitInput& req)
{
    // Global 1-in-flight: the whole VM rolls back on loadvm, so only one program
    // may be outstanding regardless of worker_id.
    if (busy_.load(std::memory_order_acquire)) return SubmitOutcome::kBusy;
    if (!EnsureSnapshotSaved()) return SubmitOutcome::kWorkerDown;
    // VM is stopped here (savevm left it stopped on first call; subsequent calls
    // re-stop below). The stop is LOAD-BEARING: the spin-waiting in-place worker
    // CAS-consumes TaskSlot, and that CAS survives loadvm (ivshmem/x-ignore-shared),
    // so writing READY while the VM runs would let the worker execute the new
    // program on pre-loadvm contaminated state AND leave TaskSlot=TAKEN that stalls
    // the restored worker. Freezing first makes the handoff deterministic.
    qmp_->Hmp("stop");
    inner_->ResetWorker(req.worker_id);   // clear last_completion_exec_seq_ (loadvm rolls it back)
    const SubmitOutcome oc = inner_->Submit(req);
    if (oc != SubmitOutcome::kSent) {
        qmp_->Hmp("cont");                // restore running; nothing in flight
        return oc;
    }
    qmp_->Hmp("loadvm " + tag_);          // rollback kernel to S0; ivshmem survives
    qmp_->Hmp("cont");                    // resume → worker polls READY, executes post-restore
    // [Brick 4a step 3] arm wedge tracking for this in-flight program.
    inflight_start_tp_    = std::chrono::steady_clock::now();
    inflight_executor_id_ = req.executor_id;
    wedge_reported_       = false;
    busy_.store(true, std::memory_order_release);
    return SubmitOutcome::kSent;
}

void SnapshotDataPlane::Poll(std::vector<DispatchOutcome>& out,
                             std::chrono::microseconds timeout)
{
    const size_t before = out.size();
    inner_->Poll(out, timeout);
    if (out.size() > before) {
        // The single in-flight program completed → free the gate for the next.
        busy_.store(false, std::memory_order_release);
        return;
    }
    // [Brick 4a step 3] VMI-on-wedge: still in-flight long past the threshold =
    // a silent hang (no CompletionSlot, and console/ssh may show nothing). Read
    // the guest's printk ring + stuck kernel PC straight from RAM, once.
    if (wedge_threshold_ms_ != 0 &&
        busy_.load(std::memory_order_acquire) && !wedge_reported_) {
        const long inflight_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - inflight_start_tp_).count();
        if (inflight_ms >= static_cast<long>(wedge_threshold_ms_)) {
            wedge_reported_ = true;
            ReadWedgeEvidence(inflight_executor_id_);
            // Latch for the WedgeRelaySensor → SnapshotRecovery(kReloadSnapshot) →
            // ResetAll → next Submit's loadvm S0 unsticks the wedged VM.
            wedge_pending_.store(true, std::memory_order_release);
        }
    }
}

void SnapshotDataPlane::WakePoller() noexcept { inner_->WakePoller(); }

void SnapshotDataPlane::ResetWorker(uint32_t worker_id)
{
    inner_->ResetWorker(worker_id);
    busy_.store(false, std::memory_order_release);
}

void SnapshotDataPlane::ResetAll()
{
    inner_->ResetAll();
    busy_.store(false, std::memory_order_release);
}

std::vector<InflightEntry> SnapshotDataPlane::SnapshotInflight() const
{
    return inner_->SnapshotInflight();
}

bool     SnapshotDataPlane::IsPaused() const noexcept     { return inner_->IsPaused(); }
bool     SnapshotDataPlane::IsClosed() const noexcept     { return inner_->IsClosed(); }
uint32_t SnapshotDataPlane::MaxWorkerSlots() const noexcept { return inner_->MaxWorkerSlots(); }

bool SnapshotDataPlane::IsWorkerSendable(uint32_t worker_id) const
{
    return !busy_.load(std::memory_order_acquire) && inner_->IsWorkerSendable(worker_id);
}

uint32_t SnapshotDataPlane::CountSendableWorkers() const
{
    if (busy_.load(std::memory_order_acquire)) return 0;
    return inner_->CountSendableWorkers();
}

// ── [Brick 4a step 3] VMI-on-wedge ──────────────────────────────────────────

void SnapshotDataPlane::ResolveLogBufVaddr()
{
    log_buf_resolved_ = true;  // attempt once regardless of outcome
    if (vmlinux_path_.empty()) return;
    // System.map sits alongside vmlinux (e.g. build-kasan/{vmlinux,System.map}).
    const auto slash = vmlinux_path_.find_last_of('/');
    const std::string dir = (slash == std::string::npos) ? "." : vmlinux_path_.substr(0, slash);
    std::ifstream map(dir + "/System.map");
    if (!map) {
        refuzz::logging::HostLineBuilder("snapshot_dp", "vmi")
            << "no System.map at " << dir << "/System.map — printk-ring VMI disabled "
            << "(PC-on-wedge still works)\n";
        return;
    }
    std::string line;
    // Match a line ending in " __log_buf" (System.map: "<hex> b __log_buf").
    static const std::string kSuffix = " __log_buf";  // 10 chars (space + 9-char symbol)
    while (std::getline(map, line)) {
        while (!line.empty() &&
               (line.back() == '\r' || line.back() == '\n' || line.back() == ' ')) {
            line.pop_back();
        }
        if (line.size() >= kSuffix.size() &&
            line.compare(line.size() - kSuffix.size(), kSuffix.size(), kSuffix) == 0) {
            log_buf_vaddr_ = std::strtoull(line.c_str(), nullptr, 16);
            break;
        }
    }
    if (log_buf_vaddr_ == 0) {
        refuzz::logging::HostLineBuilder("snapshot_dp", "vmi")
            << "__log_buf not found in System.map — printk-ring VMI disabled\n";
    }
}

void SnapshotDataPlane::ReadWedgeEvidence(uint64_t executor_id)
{
    if (!EnsureQmpConnected()) return;
    if (!log_buf_resolved_) ResolveLogBufVaddr();

    // (1) Stuck kernel PC — the one signal a silent hang never puts on console.
    std::string pc_desc = "unread";
    {
        const std::string regs = qmp_->Hmp("info registers");
        const auto p = regs.find("RIP=");
        if (p != std::string::npos) {
            const uint64_t rip = std::strtoull(regs.c_str() + p + 4, nullptr, 16);
            char sym[512] = {0};
            if (!vmlinux_path_.empty() && rip != 0) {
                char cmd[1024];
                std::snprintf(cmd, sizeof(cmd), "addr2line -e %s -f 0x%llx 2>/dev/null",
                              vmlinux_path_.c_str(), static_cast<unsigned long long>(rip));
                if (FILE* f = ::popen(cmd, "r")) {
                    std::string acc;
                    char buf[256];
                    while (std::fgets(buf, sizeof(buf), f)) acc += buf;
                    ::pclose(f);
                    for (char& c : acc) if (c == '\n') c = ' ';
                    std::snprintf(sym, sizeof(sym), "%s", acc.c_str());
                }
            }
            char d[640];
            std::snprintf(d, sizeof(d), "RIP=0x%llx %s",
                          static_cast<unsigned long long>(rip), sym);
            pc_desc = d;
        }
    }

    // (2) printk ring from guest RAM (gva2gpa __log_buf + native QMP pmemsave).
    std::string printk_tail = "unavailable";
    if (log_buf_vaddr_ != 0) {
        char g[64];
        std::snprintf(g, sizeof(g), "gva2gpa 0x%llx",
                      static_cast<unsigned long long>(log_buf_vaddr_));
        const std::string gres = qmp_->Hmp(g);
        const auto gp = gres.find("gpa: 0x");
        if (gp != std::string::npos) {
            const uint64_t gpa = std::strtoull(gres.c_str() + gp + 5, nullptr, 16);
            char path[128];
            std::snprintf(path, sizeof(path), "/tmp/refuzz_wedge_%d.bin", ::getpid());
            constexpr uint64_t kDump = 0x80000;  // 512 KiB of the ring
            char cmd[512];
            std::snprintf(cmd, sizeof(cmd),
                "{\"execute\":\"pmemsave\",\"arguments\":{\"val\":%llu,\"size\":%llu,"
                "\"filename\":\"%s\"}}",
                static_cast<unsigned long long>(gpa),
                static_cast<unsigned long long>(kDump), path);
            qmp_->Cmd(cmd);
            // Extract printable runs; keep the last ~30 plausible message lines.
            std::ifstream dump(path, std::ios::binary);
            if (dump) {
                std::vector<std::string> msgs;
                std::string cur;
                char c;
                while (dump.get(c)) {
                    if (c >= 0x20 && c < 0x7f) {
                        cur += c;
                    } else {
                        if (cur.size() >= 8) msgs.push_back(cur);
                        cur.clear();
                    }
                }
                std::string tail;
                const size_t start = msgs.size() > 30 ? msgs.size() - 30 : 0;
                for (size_t i = start; i < msgs.size(); ++i) tail += msgs[i] + " | ";
                if (!tail.empty()) printk_tail = tail;
            }
            ::unlink(path);
        }
    }

    refuzz::logging::HostLineBuilder("snapshot_dp", "wedge")
        << "VMI evidence (silent hang, host-only): executor_id=" << executor_id
        << " in_flight_ms>=" << wedge_threshold_ms_
        << " pc=[" << pc_desc << "]"
        << " printk_ring_tail=[" << printk_tail << "]\n";
}

}  // namespace refuzz::channel::data
