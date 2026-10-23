#include "refuzz/orchestrator/session_layout.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <string>
#include <system_error>
#include <unistd.h>
#include <vector>

namespace refuzz::orchestrator {

namespace fs = std::filesystem;

namespace {

std::string CurrentUtcCompact()
{
    using namespace std::chrono;
    const auto now    = system_clock::now();
    const auto tt     = system_clock::to_time_t(now);
    std::tm tm {};
    gmtime_r(&tt, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%dT%H%M%SZ", &tm);
    return buf;
}

void EnsureDir(const fs::path& p)
{
    std::error_code ec;
    fs::create_directories(p, ec);
    if (ec) {
        throw std::system_error(
            ec, "MakeSessionLayout: failed to create " + p.string());
    }
}

void ApplyRetention(const fs::path& base, uint32_t keep)
{
    if (!fs::exists(base) || !fs::is_directory(base))
        return;

    struct Entry {
        fs::path             path;
        fs::file_time_type   mtime;
    };

    std::vector<Entry> runs;
    std::error_code    ec;
    for (const auto& de : fs::directory_iterator(base, ec)) {
        if (ec) break;
        if (!de.is_directory()) continue;
        const std::string name = de.path().filename().string();
        if (name.rfind("run-", 0) != 0) continue;
        auto t = fs::last_write_time(de.path(), ec);
        if (ec) { ec.clear(); continue; }
        runs.push_back({de.path(), t});
    }

    std::sort(runs.begin(), runs.end(),
              [](const Entry& a, const Entry& b) { return a.mtime > b.mtime; });

    for (std::size_t i = keep; i < runs.size(); ++i) {
        std::error_code rm_ec;
        fs::remove_all(runs[i].path, rm_ec);
        // 忽略清理失败：retention 是 best-effort，不阻止本次 run 启动
    }
}

} // namespace

SessionLayout MakeSessionLayout(const SessionLayoutOptions& opt)
{
    const std::string base = opt.work_dir.empty() ? std::string("/tmp") : opt.work_dir;

    EnsureDir(base);

    if (!opt.retention) {
        ApplyRetention(base, opt.retention_max);
    }

    const std::string ts  = opt.timestamp_override.empty()
                                ? CurrentUtcCompact()
                                : opt.timestamp_override;
    const int         pid = opt.pid_override != 0 ? opt.pid_override
                                                  : static_cast<int>(::getpid());

    const std::string session_root =
        base + "/run-" + ts + "-" + std::to_string(pid);

    EnsureDir(session_root);

    SessionLayout out;
    out.root            = session_root;
    out.logs_dir        = session_root + "/logs";
    out.diagnostics_dir = session_root + "/diagnostics";

    // [Phase G] 只预创建瞬态子目录（logs / diagnostics）。
    //           持久数据目录 state/corpus、state/coverage、state/repros 由
    //           ParseConfigFromJson 按 state_dir 兜底并在首次写入时 lazy mkdir。
    for (const auto* sub : { &out.logs_dir, &out.diagnostics_dir }) {
        EnsureDir(*sub);
    }

    return out;
}

} // namespace refuzz::orchestrator
