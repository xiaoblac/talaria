#pragma once
// ============================================================
// SessionLayout — reFuzz 运行期工作目录布局契约
// ============================================================
//   [Phase G] SessionLayout 只管 *瞬态* 目录（本次 run 独占,可被 retention 清理）。
//
//   持久数据（corpus / coverage / repros）不再来自 SessionLayout,由
//   OrchestratorConfig::state_dir + persistence.* 独立建模,见
//   OrchestratorConfig 的 [Phase G] 注释。
//
//   语义：
//     - base = OrchestratorConfig::work_dir  (空 → "/tmp")
//     - session root = <base>/run-<ts>-<pid>/   (每次 reFuzz 进程独立)
//     - 预创建瞬态子目录 = logs / diagnostics
//     - 每 VM 子目录 = <root>/vm-<index>/      (runtime_pool Create 时 mkdir)
//     - 每 repro VM 子目录 = <root>/repro-<index>/
//
//   不变式（契约）：
//     1) MakeSessionLayout 返回后, logs / diagnostics 已 mkdir -p;vm-N/ repro-N/
//        由运行期按需创建。
//     2) MakeSessionLayout 绝不 touch 已有的 user-provided base（只在 base 下
//        创建自己的 run-*/）。
//     3) retention 策略仅扫描 <base> 下形如 "run-*" 的子目录，按 mtime 倒序
//        保留前 retention_max 个，其余 rm -rf；永远不碰 state/。
// ============================================================

#include <cstdint>
#include <string>

namespace refuzz::orchestrator {

struct SessionLayout {
    // 绝对路径，末尾无 '/'
    std::string root;
    std::string logs_dir;
    std::string diagnostics_dir;

    // "<root>/vm-<index>"（调用方自行确保目录存在即可；SessionLayout 自身
    // 只预创建顶层瞬态子目录，VM 子目录由 runtime_pool 在 Create 时 mkdir）
    inline std::string vm_dir(uint32_t index) const
    {
        return root + "/vm-" + std::to_string(index);
    }

    // "<root>/repro-<index>"（repro VM 子目录，同 vm_dir 规则）
    inline std::string repro_dir(uint32_t index) const
    {
        return root + "/repro-" + std::to_string(index);
    }
};

struct SessionLayoutOptions {
    // 用户传入的 "base 目录"。空字符串 → "/tmp"。
    std::string work_dir;

    // true: 退出时不做任何清理，所有 run-*/ 都保留。
    // false: 启动后对 <base>/run-*/ 做 retention（按 mtime 倒序保留 retention_max 个）。
    bool retention = false;

    // 仅在 retention == false 时生效。默认 3。
    uint32_t retention_max = 3;

    // 可选：覆盖默认的时戳串（单测用；生产环境留空 → 用当前 UTC 时间）。
    std::string timestamp_override;

    // 可选：覆盖默认的 pid（单测用；生产环境留空 → getpid()）。
    // 0 表示 "使用当前进程 pid"。
    int pid_override = 0;
};

// 生成 SessionLayout 并创建所有目录。
// 失败时 throw std::system_error（由 orchestrator 启动期捕获成 fatal error）。
SessionLayout MakeSessionLayout(const SessionLayoutOptions& opt);

} // namespace refuzz::orchestrator
