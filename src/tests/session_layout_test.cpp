// Phase F.9 — session_layout_test
//
// 覆盖 SessionLayout / MakeSessionLayout 的 4 个核心不变量：
//   1. user-provided work_dir → session root = <work_dir>/run-<ts>-<pid>/
//   2. default work_dir（空字符串）→ 基于 /tmp 派生
//   3. retention=false + 多个历史 run-*/ → 保留 retention_max 个
//   4. retention=true → 保留所有历史目录
//
// 使用 timestamp_override + pid_override 避开 mtime 排序抖动问题。

#include "refuzz/orchestrator/session_layout.hpp"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <thread>

namespace fs = std::filesystem;
using refuzz::orchestrator::MakeSessionLayout;
using refuzz::orchestrator::SessionLayout;
using refuzz::orchestrator::SessionLayoutOptions;

namespace {

std::string MakeTempBase(const char* label)
{
    auto base = fs::temp_directory_path()
        / (std::string("refuzz_sessionlayout_") + label + "_" +
           std::to_string(static_cast<long long>(
               std::chrono::steady_clock::now().time_since_epoch().count())));
    std::error_code ec;
    fs::remove_all(base, ec);
    fs::create_directories(base, ec);
    assert(!ec);
    return base.string();
}

void AssertDirExists(const std::string& p)
{
    std::error_code ec;
    assert(fs::is_directory(p, ec));
}

void TestUserProvidedRoot()
{
    const std::string base = MakeTempBase("user");

    SessionLayoutOptions opt;
    opt.work_dir          = base;
    opt.retention         = true;
    opt.timestamp_override = "20990101T000000Z";
    opt.pid_override       = 9999;

    SessionLayout L = MakeSessionLayout(opt);

    assert(L.root == base + "/run-20990101T000000Z-9999");
    assert(L.logs_dir        == L.root + "/logs");
    assert(L.diagnostics_dir == L.root + "/diagnostics");
    assert(L.vm_dir(0)       == L.root + "/vm-0");
    assert(L.vm_dir(7)       == L.root + "/vm-7");
    assert(L.repro_dir(2)    == L.root + "/repro-2");

    // [Phase G] 只预创建瞬态子目录（logs/diagnostics）。
    //           corpus/coverage/repros 已从 SessionLayout 移除,改由 state_dir 接管。
    AssertDirExists(L.root);
    AssertDirExists(L.logs_dir);
    AssertDirExists(L.diagnostics_dir);

    std::error_code ec;
    fs::remove_all(base, ec);
}

void TestDefaultBase()
{
    SessionLayoutOptions opt;
    // work_dir 空 → 默认 /tmp
    opt.retention          = true;   // 不清理 /tmp 下其他 run-*
    opt.timestamp_override = "20990101T000001Z";
    opt.pid_override       = 9998;

    SessionLayout L = MakeSessionLayout(opt);

    assert(L.root.rfind("/tmp/run-20990101T000001Z-9998", 0) == 0);
    AssertDirExists(L.root);
    AssertDirExists(L.logs_dir);

    std::error_code ec;
    fs::remove_all(L.root, ec);
}

void TestRetentionKeepsMost()
{
    const std::string base = MakeTempBase("retention");

    auto create_run = [&](const std::string& name) {
        std::error_code ec;
        fs::create_directories(base + "/" + name, ec);
        assert(!ec);
        std::ofstream((base + "/" + name + "/marker")).put('x');
    };

    // 造 5 个历史 run-*；每个之间 sleep 10ms 让 mtime 有序
    for (int i = 0; i < 5; ++i) {
        create_run("run-hist-" + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // 再造一个非 run-* 目录，确认不会被误删
    std::error_code ec;
    fs::create_directories(base + "/keep-me", ec);

    SessionLayoutOptions opt;
    opt.work_dir           = base;
    opt.retention          = false;
    opt.retention_max      = 3;   // 保留 3 个最新；本次还会新建一个，留下来
    opt.timestamp_override = "20990101T000002Z";
    opt.pid_override       = 9997;

    SessionLayout L = MakeSessionLayout(opt);

    // 现场 run-* = 3 个最新 hist + 本次；非 run-* 的 keep-me 仍在
    assert(fs::is_directory(base + "/keep-me"));
    assert(fs::is_directory(L.root));

    // 检查最老的两个被删（run-hist-0、run-hist-1）
    assert(!fs::exists(base + "/run-hist-0"));
    assert(!fs::exists(base + "/run-hist-1"));
    // run-hist-2/3/4 至少保留
    assert(fs::is_directory(base + "/run-hist-2"));
    assert(fs::is_directory(base + "/run-hist-3"));
    assert(fs::is_directory(base + "/run-hist-4"));

    fs::remove_all(base, ec);
}

void TestRetentionTrueKeepsAll()
{
    const std::string base = MakeTempBase("retainall");

    std::error_code ec;
    fs::create_directories(base + "/run-hist-A", ec);
    fs::create_directories(base + "/run-hist-B", ec);
    fs::create_directories(base + "/run-hist-C", ec);

    SessionLayoutOptions opt;
    opt.work_dir           = base;
    opt.retention          = true;
    opt.retention_max      = 1;
    opt.timestamp_override = "20990101T000003Z";
    opt.pid_override       = 9996;

    SessionLayout L = MakeSessionLayout(opt);

    assert(fs::is_directory(base + "/run-hist-A"));
    assert(fs::is_directory(base + "/run-hist-B"));
    assert(fs::is_directory(base + "/run-hist-C"));
    assert(fs::is_directory(L.root));

    fs::remove_all(base, ec);
}

} // namespace

int main()
{
    TestUserProvidedRoot();
    TestDefaultBase();
    TestRetentionKeepsMost();
    TestRetentionTrueKeepsAll();
    std::printf("session_layout_test: OK\n");
    return 0;
}
